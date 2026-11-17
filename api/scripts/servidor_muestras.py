import functools
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import time
from urllib.parse import parse_qs, urlparse

MUESTRAS = Path(__file__).resolve().parents[2] / "samples"


class Descarga(SimpleHTTPRequestHandler):
    def end_headers(self):
        self.send_header("Cache-Control", "no-store")
        if not self.path.endswith("/"):
            self.send_header("Content-Disposition", "attachment")
        super().end_headers()

    def do_GET(self):
            ruta = urlparse(self.path)
            if not ruta.path.startswith("/lento"):
                return super().do_GET()
            segundos = int(parse_qs(ruta.query).get("seg", ["10"])[0])
            trozos, tam = 100, 100_000  # 10 MB en total
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(trozos * tam))
            self.end_headers()
            try:
                for _ in range(trozos):
                    self.wfile.write(b"\0" * tam)
                    time.sleep(segundos / trozos)
            except (BrokenPipeError, ConnectionResetError):
                pass  # el navegador canceló la descarga


manejador = functools.partial(Descarga, directory=str(MUESTRAS))
print(f"Sirviendo {MUESTRAS} en http://127.0.0.1:9000 (Ctrl+C para detener)")
ThreadingHTTPServer(("127.0.0.1", 9000), manejador).serve_forever()
