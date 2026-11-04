import yara
import re
from collections import Counter
from api.motor import RAIZ_REGLAS, severidad_de

conteo = Counter()
for ruta in sorted(RAIZ_REGLAS.rglob("*")):
    if ruta.suffix in {".yar", ".yara"}:
        namespace = re.sub(r"\W", "_", ruta.relative_to(RAIZ_REGLAS).as_posix())
        for regla in yara.compile(filepath=str(ruta)):
            conteo[severidad_de(regla.identifier, regla.meta, namespace)] += 1

print(dict(conteo), "| total:", sum(conteo.values()))
