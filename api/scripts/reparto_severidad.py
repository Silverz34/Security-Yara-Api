import yara
import re
from collections import Counter
from api.motor import RAIZ_REGLAS, severidad_de, VARIABLES_CONTEXTO, categoria_de

conteo = Counter()
categorias = Counter()
for ruta in sorted(RAIZ_REGLAS.rglob("*")):
    if ruta.suffix in {".yar", ".yara"}:
        namespace = re.sub(r"\W", "_", ruta.relative_to(RAIZ_REGLAS).as_posix())
        for regla in yara.compile(filepath=str(ruta), externals=VARIABLES_CONTEXTO):
            conteo[severidad_de(regla.identifier, regla.meta, namespace)] += 1
            categorias[categoria_de(regla.identifier, namespace)] += 1

print(dict(conteo), "| total:", sum(conteo.values()))
print(dict(categorias))
