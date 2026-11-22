import hashlib
import re
from api.db import crear_tablas, guardar_escaneo, consultar_cache, estadisticas
from typing import Annotated
from fastapi import FastAPI, File, Form, HTTPException, UploadFile, Query, Request, UploadFile
from api.motor import escanear, RULES_VERSION, CATEGORIAS
from api.config import (
    BODY_MARGIN_BYTES, MAX_EXTENSION, MAX_FILENAME, MAX_MIME, MAX_SOURCE_DOMAIN, MAX_UPLOAD_BYTES)
from fastapi.responses import JSONResponse

SUFIJO_CHROME = re.compile(r" \(\d+\)(?=(\.[^./\\]*)?$)")

def preparar_nombre(filename: str) -> str:
    if "/" in filename or "\\" in filename:
        raise HTTPException(400, "filename debe ser solo el nombre, sin ruta")
    return SUFIJO_CHROME.sub("", filename, count=1)

app = FastAPI(title="SecureYara API")
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


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/scan")
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
    resultado = escanear(datos, contexto)
    if scan_mode not in {"principal", "degradado"}:
        scan_mode = "principal"
    guardar_escaneo(sha256.lower(), len(datos), contexto, resultado, scan_mode)
    return resultado


@app.get("/verdicts/{sha256}")
def verdicto_guardado(
    sha256: str,
    filename: Annotated[str, Query(max_length=MAX_FILENAME)],
    mime: Annotated[str, Query(max_length=MAX_MIME)] = "",
    source_domain: Annotated[str, Query(max_length=MAX_SOURCE_DOMAIN)] = "",
    scan_mode: str = "principal",
):
    if not re.fullmatch(r"[0-9a-f]{64}", sha256.lower()):
        raise HTTPException(400, "sha256 inválido")
    if scan_mode not in {"principal", "degradado"}:
        scan_mode = "principal"
    resultado = consultar_cache(
        sha256.lower(), preparar_nombre(filename), mime, source_domain, RULES_VERSION, scan_mode
    )
    if resultado is None:
        raise HTTPException(404, "Sin veredicto guardado para estos datos")
    return resultado


@app.get("/stats")
def estadisticas_generales():
    datos = estadisticas()
    for c in datos["categorias"]:
        c.update(CATEGORIAS.get(c["categoria"], CATEGORIAS["otra"]))
    return datos
