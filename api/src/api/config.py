#configuracion central de la api
import os


def _entero(nombre:str, defecto: int, minimo: int = 1) -> int:
    crudo = os.getenv(nombre, "").strip()
    if not crudo :
        return defecto
    try:
        valor = int(crudo)
    except ValueError:
        raise RuntimeError(f"{nombre} debe ser un entero, recibido: {crudo!r}") from None
    if valor < minimo:
        raise RuntimeError(f"{nombre} debe ser >= {minimo}, recibido: {valor}")
    return valor



def _booleano(nombre:str, defecto: bool) -> bool:
    crudo = os.getenv(nombre, "").strip().lower()

    if not crudo:
        return defecto
    return crudo in {"true", "yes", "1"}

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///secureyara.db")
MAX_UPLOAD_BYTES = _entero("MAX_UPLOAD_BYTES", 25 * 1024 * 1024)


#se usaran más adelante
SCAN_TIMEOUT_S = _entero("SCAN_TIMEOUT_S", 15)
MAX_CONCURRENT_SCANS = _entero("MAX_CONCURRENT_SCANS", 2)
API_KEY = os.getenv("API_KEY", "").strip()
ENABLE_DOCS = _booleano("ENABLE_DOCS", True)
