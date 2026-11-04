import re
from functools import cache
from pathlib import Path

import yara

RAIZ_REGLAS = Path(__file__).resolve().parents[2] / "rules"

@cache
def cargar_reglas() -> yara.Rules:
    archivos = {}
    for ruta in sorted(RAIZ_REGLAS.rglob("*")):
        if ruta.suffix in {".yar", ".yara"}:
            relativa = ruta.relative_to(RAIZ_REGLAS).as_posix()
            namespace = re.sub(r"\W", "_", relativa)
            archivos[namespace] = str(ruta)
    return yara.compile(filepaths=archivos)

ORDEN_SEVERIDAD = {"low": 1, "medium": 2, "high": 3}
SEVERIDAD_POR_DEFECTO = "medium"
RULES_VERSION = (RAIZ_REGLAS / "vendor" / "COMMIT.txt").read_text().strip()[:7]


def escanear(datos: bytes) -> dict:
    coincidencias = []
    for m in cargar_reglas().match(data=datos):
        severidad = m.meta.get("severity", SEVERIDAD_POR_DEFECTO)
        if severidad not in ORDEN_SEVERIDAD:
            severidad = SEVERIDAD_POR_DEFECTO
        coincidencias.append(
            {
                "rule": m.rule,
                "title_es": m.meta.get("title_es", m.rule),
                "explanation_es": m.meta.get(
                    "explanation_es", "El archivo coincide con una regla de detección conocida."
                ),
                "recommendation_es": m.meta.get(
                    "recommendation_es", "No lo abras si no confías en su origen."
                ),
                "severity": severidad,
                "category": m.meta.get("category", "general"),
            }
        )

    if not coincidencias:
        return {"verdict": "limpio", "severity": None, "matches": [], "rules_version": RULES_VERSION}

    mayor = max(coincidencias, key=lambda c: ORDEN_SEVERIDAD[c["severity"]])["severity"]
    veredicto = "peligroso" if mayor == "high" else "sospechoso"
    return {
        "verdict": veredicto,
        "severity": mayor,
        "matches": coincidencias,
        "rules_version": RULES_VERSION,
    }
