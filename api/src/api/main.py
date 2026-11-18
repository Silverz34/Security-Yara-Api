import hashlib
from api.db import crear_tablas, guardar_escaneo
from typing import Annotated
from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from api.motor import escanear


LIMITE_BYTES = 25 * 1024 * 1024

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
    if "/" in filename or "\\" in filename:
        raise HTTPException(400, "filename debe ser solo el nombre, sin ruta")

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
