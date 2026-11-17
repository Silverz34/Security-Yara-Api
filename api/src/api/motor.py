import re
from functools import cache
from pathlib import Path

import yara

CATEGORIAS = {
    "familia_malware": {
        "nombre_es": "Malware de una familia conocida",
        "explicacion_es": "El archivo coincide con la firma de una familia de malware conocida.",
        "recomendacion_es": "Elimínalo y no lo ejecutes.",
    },
    "exploit_cve": {
        "nombre_es": "Exploit de vulnerabilidad conocida",
        "explicacion_es": "El archivo contiene un patrón asociado a una vulnerabilidad conocida, que un atacante podría aprovechar al abrirlo.",
        "recomendacion_es": "Elimínalo y no lo abras con programas sin actualizar.",
    },
    "kit_exploits": {
        "nombre_es": "Kit de exploits",
        "explicacion_es": "El patrón corresponde a herramientas que atacan al navegador o a sus complementos desde páginas web.",
        "recomendacion_es": "Elimínalo y desconfía del sitio de origen.",
    },
    "documento_malicioso": {
        "nombre_es": "Documento malicioso",
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
RULES_VERSION = (RAIZ_REGLAS / "vendor" / "COMMIT.txt").read_text().strip()[:7]
VARIABLES_CONTEXTO = {"filename": "", "extension": "", "mime": "", "source_domain": ""}


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


def escanear(datos: bytes, contexto: dict | None = None) -> dict:
    coincidencias = []
    for m in cargar_reglas().match(
        data=datos, externals={**VARIABLES_CONTEXTO, **(contexto or {})}
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
    veredicto = "peligroso" if mayor == "high" else "sospechoso"
    return {
        "verdict": veredicto,
        "severity": mayor,
        "matches": coincidencias,
        "rules_version": RULES_VERSION,
        "main_category": categoria_principal(coincidencias),
    }
