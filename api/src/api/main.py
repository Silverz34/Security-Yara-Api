import hashlib
import re
from api.db import crear_tablas, guardar_escaneo, consultar_cache, estadisticas
from typing import Annotated
from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from api.motor import escanear, RULES_VERSION, CATEGORIAS


LIMITE_BYTES = 25 * 1024 * 1024
SUFIJO_CHROME = re.compile(r" \(\d+\)(?=(\.[^./\\]*)?$)")

def preparar_nombre(filename: str) -> str:
    if "/" in filename or "\\" in filename:
        raise HTTPException(400, "filename debe ser solo el nombre, sin ruta")
    return SUFIJO_CHROME.sub("", filename, count=1)

app = FastAPI(title="SecureYara API")
crear_tablas()


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/scan")
def scan(
    file: Annotated[UploadFile, File()],
    sha256: Annotated[str, Form()],
    filename: Annotated[str, Form()],
    extension: Annotated[str, Form()] = "",
    mime: Annotated[str, Form()] = "",
    source_domain: Annotated[str, Form()] = "",
    scan_mode: Annotated[str, Form()] = "principal",

):
    filename = preparar_nombre(filename)
    datos = file.file.read(LIMITE_BYTES + 1)
    if len(datos) > LIMITE_BYTES:
        raise HTTPException(413, "El archivo excede 25 MB")
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
    filename: str,
    mime: str = "",
    source_domain: str = "",
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
