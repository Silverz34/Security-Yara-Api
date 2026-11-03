import re
import sys
from pathlib import Path

import yara

RAIZ = Path(__file__).resolve().parent.parent / "rules" / "vendor"
PATRON_REGLA = re.compile(r"^\s*(?:(?:private|global)\s+)*rule\s+\w+", re.MULTILINE)

archivos = sorted(p for p in RAIZ.rglob("*") if p.suffix in {".yar", ".yara"})
compilan = 0
total_reglas = 0
fallan = []

for ruta in archivos:
    try:
        yara.compile(filepath=str(ruta))
        compilan += 1
        total_reglas += len(PATRON_REGLA.findall(ruta.read_text(errors="ignore")))
    except yara.Error as e:
        fallan.append((ruta.relative_to(RAIZ), str(e)))

print(f"Archivos: {len(archivos)} | compilan: {compilan} | fallan: {len(fallan)}")
print(f"Reglas (aprox.) en los archivos que compilan: {total_reglas}")

for ruta, error in fallan:
    print(f"\n[FALLA] {ruta}\n  {error}")

sys.exit(1 if fallan else 0)
