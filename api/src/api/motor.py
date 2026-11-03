import re
from pathlib import Path

import yara

RAIZ_REGLAS = Path(__file__).resolve().parents[2] / "rules"


def cargar_reglas() -> yara.Rules:
    archivos = {}
    for ruta in sorted(RAIZ_REGLAS.rglob("*")):
        if ruta.suffix in {".yar", ".yara"}:
            relativa = ruta.relative_to(RAIZ_REGLAS).as_posix()
            namespace = re.sub(r"\W", "_", relativa)
            archivos[namespace] = str(ruta)
    return yara.compile(filepaths=archivos)
