from starlette.types import HTTPExceptionHandler
import threading, yara, logging
import hashlib
import secrets
import re
from api.db import crear_tablas, guardar_escaneo, consultar_cache, estadisticas
from typing import Annotated
from fastapi import FastAPI, File, Form, HTTPException, UploadFile,Request,Depends, Header
from api.motor import escanear, RULES_VERSION, CATEGORIAS
from api.config import (
    BODY_MARGIN_BYTES, MAX_EXTENSION, MAX_FILENAME, MAX_MIME, MAX_SOURCE_DOMAIN, MAX_UPLOAD_BYTES, MAX_CONCURRENT_SCANS, SCAN_QUEUE_WAIT_S, API_KEY, ENABLE_DOCS)
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field


SUFIJO_CHROME = re.compile(r" \(\d+\)(?=(\.[^./\\]*)?$)")

def preparar_nombre(filename: str) -> str:
    if "/" in filename or "\\" in filename:
        raise HTTPException(400, "filename debe ser solo el nombre, sin ruta")
    return SUFIJO_CHROME.sub("", filename, count=1)

app = FastAPI(
    title="SecureYara API",
    docs_url="/docs" if ENABLE_DOCS else None,
    redoc_url="/redoc" if ENABLE_DOCS else None,
    openapi_url="/openapi.json" if ENABLE_DOCS else None)
crear_tablas()

@app.middleware("http")
async def limitar_cuerpo(request: Request, call_next):
    longitud = request.headers.get("content-length")
    if longitud is not None:
        try:
            demasiado_grande = int(longitud) > MAX_UPLOAD_BYTES + BODY_MARGIN_BYTES
        except ValueError:
            return JSONResponse({"detail": "Content-Length inválido"}, status_code=400)
        if demasiado_grande:
            return JSONResponse(
                {"detail": "El cuerpo de la petición es demasiado grande"},
                status_code=413,
            )
    return await call_next(request)

logger = logging.getLogger("secureyara")
semaforo_escaneos = threading.BoundedSemaphore(MAX_CONCURRENT_SCANS)

if not API_KEY:
    logger.warning("API_KEY vacía: la API no exige clave (solo para desarrollo)")

def verificar_clave(x_api_key: Annotated[str | None, Header()] = None):
    if not API_KEY:
        return
    if x_api_key is None or not secrets.compare_digest(
        x_api_key.encode(), API_KEY.encode()
    ):
        raise HTTPException(401, "Clave de API inválida o ausente")

def turno_de_escaneo():
    if not semaforo_escaneos.acquire(timeout=SCAN_QUEUE_WAIT_S):
        raise HTTPException(
            503, "Servidor ocupado, intenta de nuevo", headers={"Retry-After": "2"}
        )
    try:
        yield
    finally:
        semaforo_escaneos.release()





# Endpoits
@app.exception_handler(Exception)
async def error_inesperado(request: Request, exc: Exception):
    logger.exception("Error no controlado en %s %s", request.method, request.url.path)
    return JSONResponse({"detail": "Error interno del servidor"}, status_code=500)


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/scan", dependencies = [Depends(verificar_clave), Depends(turno_de_escaneo)])
def scan(
    file: Annotated[UploadFile, File()],
    sha256: Annotated[str, Form()],
    filename: Annotated[str, Form(max_length=MAX_FILENAME)],
    extension: Annotated[str, Form(max_length=MAX_EXTENSION)] = "",
    mime: Annotated[str, Form(max_length=MAX_MIME)] = "",
    source_domain: Annotated[str, Form(max_length=MAX_SOURCE_DOMAIN)] = "",
    scan_mode: Annotated[str, Form()] = "principal",

):
    filename = preparar_nombre(filename)
    datos = file.file.read(MAX_UPLOAD_BYTES + 1)
    if len(datos) > MAX_UPLOAD_BYTES:
        raise HTTPException(413, f"El archivo excede {MAX_UPLOAD_BYTES/(1024 * 1024):g}MB")
    if hashlib.sha256(datos).hexdigest() != sha256.lower():
        raise HTTPException(400, "El SHA-256 no coincide con el archivo")
    contexto = {
        "filename": filename,
        "extension": extension.lower().lstrip("."),
        "mime": mime,
        "source_domain": source_domain,
    }
    try :
        resultado = escanear(datos, contexto)
    except yara.TimeoutError:
         raise HTTPException(504, "El escaneo tardó demasiado") from None
    if scan_mode not in {"principal", "degradado"}:
        scan_mode = "principal"
    guardar_escaneo(sha256.lower(), len(datos), contexto, resultado, scan_mode)
    return resultado


class ConsultaVeredicto(BaseModel):
    sha256: str = Field(pattern=r"^[0-9a-fA-F]{64}$")
    filename: str = Field(max_length=MAX_FILENAME)
    mime: str = Field(default="", max_length=MAX_MIME)
    source_domain: str = Field(default="", max_length=MAX_SOURCE_DOMAIN)
    scan_mode: str = Field(default="principal", max_length=16)

@app.post("/verdicts/lookup", dependencies=[Depends(verificar_clave)])
def consultar_veredicto(consulta: ConsultaVeredicto):
    scan_mode = (
        consulta.scan_mode if consulta.scan_mode in {"principal", "degradado"} else "principal"
    )
    resultado = consultar_cache(
        consulta.sha256.lower(),
        preparar_nombre(consulta.filename),
        consulta.mime,
        consulta.source_domain,
        RULES_VERSION,
        scan_mode,
    )
    if resultado is None:
        raise HTTPException(404, "Sin veredicto guardado para estos datos")
    return resultado


@app.get("/stats", dependencies = [Depends(verificar_clave), Depends(turno_de_escaneo)])
def estadisticas_generales():
    datos = estadisticas()
    for c in datos["categorias"]:
        c.update(CATEGORIAS.get(c["categoria"], CATEGORIAS["otra"]))
    return datos
