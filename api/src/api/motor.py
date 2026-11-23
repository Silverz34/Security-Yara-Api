import re
from functools import cache
from pathlib import Path
import hashlib
from socket import timeout
from api.config import SCAN_TIMEOUT_S
import yara
import io
import time
import zipfile
import zlib
from api.config import MAX_UPLOAD_BYTES, SCAN_TIMEOUT_S, ZIP_MAX_ENTRIES, ZIP_MAX_TOTAL_BYTES

timeout=timeout or SCAN_TIMEOUT_S

CATEGORIAS = {
    "familia_malware": {
        "nombre_es": "Familia de Malware",
        "explicacion_es": "El archivo coincide con la firma de una familia de malware conocida.",
        "recomendacion_es": "Elimínalo y no lo ejecutes.",
    },
    "exploit_cve": {
        "nombre_es": "Exploit CVE",
        "explicacion_es": "El archivo contiene un patrón asociado a una vulnerabilidad conocida, que un atacante podría aprovechar al abrirlo.",
        "recomendacion_es": "Elimínalo y no lo abras con programas sin actualizar.",
    },
    "kit_exploits": {
        "nombre_es": "Kit de exploits",
        "explicacion_es": "El patrón corresponde a herramientas que atacan al navegador o a sus complementos desde páginas web.",
        "recomendacion_es": "Elimínalo y desconfía del sitio de origen.",
    },
    "documento_malicioso": {
        "nombre_es": "Doc. malicioso",
        "explicacion_es": "El documento contiene elementos que se usan para ejecutar código sin que lo notes, como macros u objetos incrustados.",
        "recomendacion_es": "No habilites macros ni contenido activo, y ábrelo solo si confías en su origen.",
    },
    "engano_contexto": {
        "nombre_es": "Engaño de contexto",
        "explicacion_es": "El archivo no coincide con lo que aparenta ser por su nombre, extensión, tipo u origen.",
        "recomendacion_es": "Elimínalo, salvo que estés seguro de su origen.",
    },
    "prueba": {
        "nombre_es": "Archivo de prueba",
        "explicacion_es": "Es un archivo de prueba de antivirus. No es dañino.",
        "recomendacion_es": "Elimínalo si no lo descargaste a propósito.",
    },
    "otra": {
        "nombre_es": "Otra detección",
        "explicacion_es": "El archivo coincide con una regla de detección conocida.",
        "recomendacion_es": "No lo abras si no confías en su origen.",
    },
}

CATEGORIA_POR_NAMESPACE = {
    "vendor_maldocs_": "documento_malicioso",
    "vendor_cve_rules_": "exploit_cve",
    "vendor_exploit_kits_": "kit_exploits",
    "vendor_malware_": "familia_malware",
    "custom_contexto_": "engano_contexto",
    "custom_eicar_": "prueba",
}
PATRON_CVE = re.compile(r"cve[_-]?(\d{4})[_-]?(\d{4,7})", re.IGNORECASE)

RAIZ_REGLAS = Path(__file__).resolve().parents[2] / "rules"
ORDEN_SEVERIDAD = {"low": 1, "medium": 2, "high": 3}
SEVERIDAD_POR_REGLA = {
    "RTFFILE": "low",
    "Word_2007_XML_Flat_OPC": "low",
    "BlackHole_v2": "high",
}
SEVERIDAD_POR_CATEGORIA = {
    "vendor_maldocs_": "medium",
    "vendor_cve_rules_": "high",
    "vendor_exploit_kits_": "high",
    "vendor_malware_": "high",
}
SEVERIDAD_POR_DEFECTO = "medium"
VARIABLES_CONTEXTO = {"filename": "", "extension": "", "mime": "", "source_domain": ""}

def version_reglas() -> str:
    h = hashlib.sha256()
    for ruta in sorted(RAIZ_REGLAS.rglob("*")):
        if ruta.suffix in {".yar", ".yara"}:
            h.update(ruta.read_bytes())
    return h.hexdigest()[:7]
RULES_VERSION = version_reglas()

@cache
def cargar_reglas() -> yara.Rules:
    archivos = {}
    for ruta in sorted(RAIZ_REGLAS.rglob("*")):
        if ruta.suffix in {".yar", ".yara"}:
            relativa = ruta.relative_to(RAIZ_REGLAS).as_posix()
            namespace = re.sub(r"\W", "_", relativa)
            archivos[namespace] = str(ruta)
    return yara.compile(filepaths=archivos, externals=VARIABLES_CONTEXTO)


def severidad_de(regla: str, meta: dict, namespace: str) -> str:
    if SEVERIDAD_POR_REGLA.get(regla) in ORDEN_SEVERIDAD:
        return SEVERIDAD_POR_REGLA[regla]
    if meta.get("severity") in ORDEN_SEVERIDAD:
        return meta["severity"]
    if isinstance(meta.get("weight"), int):
        return "low"
    if "cve" in regla.lower():
        return "high"
    if isinstance(meta.get("score"), int):
        return "high" if meta["score"] >= 70 else "medium"
    for prefijo, severidad in SEVERIDAD_POR_CATEGORIA.items():
        if namespace.startswith(prefijo):
            return severidad
    return SEVERIDAD_POR_DEFECTO


def categoria_de(regla: str, namespace: str) -> str:
    if "cve" in regla.lower():
        return "exploit_cve"
    for prefijo, categoria in CATEGORIA_POR_NAMESPACE.items():
        if namespace.startswith(prefijo):
            return categoria
    return "otra"


def codigo_cve(regla: str) -> str | None:
    m = PATRON_CVE.search(regla)
    return f"CVE-{m.group(1)}-{m.group(2)}" if m else None


def categoria_principal(coincidencias: list) -> str | None:
    relevantes = [c for c in coincidencias if c["severity"] != "low"]
    if not relevantes:
        return None
    prioridad = list(CATEGORIAS)
    mejor = min(
        relevantes,
        key=lambda c: (-ORDEN_SEVERIDAD[c["severity"]], prioridad.index(c["category"])),
    )
    return mejor["category"]

def escanear(datos: bytes, contexto: dict | None = None, timeout: int | None = None) -> dict:
    coincidencias = []
    for m in cargar_reglas().match(
        data=datos, externals={**VARIABLES_CONTEXTO, **(contexto or {})}, timeout= SCAN_TIMEOUT_S
    ):
        severidad = severidad_de(m.rule, m.meta, m.namespace)
        categoria = categoria_de(m.rule, m.namespace)
        info = CATEGORIAS[categoria]
        cve = codigo_cve(m.rule)
        coincidencias.append(
            {
                "rule": m.rule,
                "title_es": m.meta.get("title_es", info["nombre_es"]),
                "explanation_es": m.meta.get(
                    "explanation_es", info["explicacion_es"] + (f" ({cve})" if cve else "")
                ),
                "recommendation_es": m.meta.get("recommendation_es", info["recomendacion_es"]),
                "severity": severidad,
                "category": categoria,
                "description": str(m.meta.get("description", "")),
            }
        )

    return resumir(coincidencias)


def resumir(coincidencias: list) -> dict:
    relevantes = [c for c in coincidencias if c["severity"] != "low"]
    if not relevantes:
        return {
            "verdict": "limpio",
            "severity": None,
            "matches": coincidencias,
            "rules_version": RULES_VERSION,
            "main_category": None,
        }
    mayor = max(relevantes, key=lambda c: ORDEN_SEVERIDAD[c["severity"]])["severity"]
    return {
        "verdict": "peligroso" if mayor == "high" else "sospechoso",
        "severity": mayor,
        "matches": coincidencias,
        "rules_version": RULES_VERSION,
        "main_category": categoria_principal(coincidencias),
    }


def _restante(limite: float) -> int:
    segundos = limite - time.monotonic()
    if segundos <= 0:
        raise yara.TimeoutError("tiempo total de escaneo agotado")
    return max(1, int(segundos))


def _contexto_de_entrada(nombre_interno: str, contexto: dict) -> dict:
    nombre = nombre_interno.replace("\\", "/").rsplit("/", 1)[-1][:255]
    extension = nombre.rsplit(".", 1)[-1].lower()[:32] if "." in nombre else ""
    return {
        "filename": nombre,
        "extension": extension,
        "mime": "",
        "source_domain": contexto.get("source_domain", ""),
    }


def escanear_con_zip(datos: bytes, contexto: dict | None = None) -> dict:
    contexto = contexto or {}
    limite = time.monotonic() + SCAN_TIMEOUT_S
    resultado = escanear(datos, contexto, timeout=SCAN_TIMEOUT_S)

    es_zip = (
        contexto.get("extension") == "zip" or contexto.get("mime") == "application/zip"
    ) and datos[:4] == b"PK\x03\x04"
    if not es_zip:
        return resultado
    try:
        zf = zipfile.ZipFile(io.BytesIO(datos))
    except zipfile.BadZipFile:
        return resultado

    coincidencias = list(resultado["matches"])
    total = 0
    with zf:
        entradas = [i for i in zf.infolist() if not i.is_dir()][:ZIP_MAX_ENTRIES]
        for info in entradas:
            if info.flag_bits & 0x1:  # cifrado: no se puede inspeccionar
                continue
            if info.file_size > MAX_UPLOAD_BYTES or total + info.file_size > ZIP_MAX_TOTAL_BYTES:
                continue
            try:
                with zf.open(info) as f:
                    contenido = f.read(MAX_UPLOAD_BYTES + 1)
            except (zipfile.BadZipFile, NotImplementedError, RuntimeError, EOFError, zlib.error):
                continue
            total += len(contenido)
            r = escanear(
                contenido,
                _contexto_de_entrada(info.filename, contexto),
                timeout=_restante(limite),
            )
            for m in r["matches"]:
                coincidencias.append(
                    {
                        **m,
                        "explanation_es": f"{m['explanation_es']} (dentro del ZIP: {info.filename})",
                        "archivo_interno": info.filename,
                    }
                )
    return resumir(coincidencias)
