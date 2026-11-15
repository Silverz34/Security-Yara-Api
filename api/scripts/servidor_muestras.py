import functools
from http.server import HTTPServer, SimpleHTTPRequestHandler
from pathlib import Path

MUESTRAS = Path(__file__).resolve().parents[2] / "samples"


class Descarga(SimpleHTTPRequestHandler):
    def end_headers(self):
        if not self.path.endswith("/"):
            self.send_header("Content-Disposition", "attachment")
        super().end_headers()


manejador = functools.partial(Descarga, directory=str(MUESTRAS))
print(f"Sirviendo {MUESTRAS} en http://127.0.0.1:9000 (Ctrl+C para detener)")
HTTPServer(("127.0.0.1", 9000), manejador).serve_forever()
