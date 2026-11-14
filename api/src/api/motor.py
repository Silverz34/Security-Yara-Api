import re
from functools import cache
from pathlib import Path

import yara

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


def escanear(datos: bytes, contexto: dict | None = None) -> dict:
    coincidencias = []
    for m in cargar_reglas().match(
        data=datos, externals={**VARIABLES_CONTEXTO, **(contexto or {})}
    ):
        severidad = m.meta.get("severity", SEVERIDAD_POR_DEFECTO)
        if severidad not in ORDEN_SEVERIDAD:
            severidad = SEVERIDAD_POR_DEFECTO
        coincidencias.append(
            {
                "rule": m.rule,
                "title_es": m.meta.get("title_es", m.rule),
                "explanation_es": m.meta.get(
                    "explanation_es",
                    "El archivo coincide con una regla de detección conocida.",
                ),
                "recommendation_es": m.meta.get(
                    "recommendation_es", "No lo abras si no confías en su origen."
                ),
                "severity": severidad,
                "category": m.meta.get("category", "general"),
            }
        )

    relevantes = [c for c in coincidencias if c["severity"] != "low"]
    if not relevantes:
        return {
            "verdict": "limpio",
            "severity": None,
            "matches": coincidencias,
            "rules_version": RULES_VERSION,
        }

    mayor = max(relevantes, key=lambda c: ORDEN_SEVERIDAD[c["severity"]])["severity"]
    veredicto = "peligroso" if mayor == "high" else "sospechoso"
    return {
        "verdict": veredicto,
        "severity": mayor,
        "matches": coincidencias,
        "rules_version": RULES_VERSION,
    }
