"""Start the portal over HTTPS (https://localhost:5000) with an HTTP->HTTPS redirect on port 5080."""
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

from werkzeug.serving import WSGIRequestHandler

sys.path.insert(0, str(Path(__file__).resolve().parent / "scripts"))

from app import create_app          # noqa: E402
from make_cert import make_cert     # noqa: E402

app = create_app()
cfg = app.config


class RedirectToHttps(BaseHTTPRequestHandler):
    def _redirect(self):
        self.send_response(301)
        self.send_header("Location", "https://%s:%d/" % (cfg["PUBLIC_HOST"], cfg["HTTPS_PORT"]))
        self.end_headers()

    do_GET = do_POST = do_HEAD = _redirect

    def log_message(self, *args):
        pass


class QuietHandler(WSGIRequestHandler):
    """Stops the development server adding its own 'Server: Werkzeug/x Python/x' banner (information leak).
    The app sets a neutral Server header itself. In production Nginx also hides it (see deploy/nginx.conf)."""

    def send_response(self, code, message=None):
        self.log_request(code)
        self.send_response_only(code, message)
        self.send_header("Date", self.date_time_string())


def main():
    cert, key = make_cert(Path(app.instance_path) / "certs")
    redirector = HTTPServer(("127.0.0.1", cfg["HTTP_REDIRECT_PORT"]), RedirectToHttps)
    threading.Thread(target=redirector.serve_forever, daemon=True).start()
    print("Portal:  https://localhost:%d   (self-signed certificate: accept the browser warning)" % cfg["HTTPS_PORT"])
    print("Plain HTTP on port %d redirects to HTTPS." % cfg["HTTP_REDIRECT_PORT"])
    app.run(host="127.0.0.1", port=cfg["HTTPS_PORT"], ssl_context=(str(cert), str(key)), debug=False,
            request_handler=QuietHandler)


if __name__ == "__main__":
    main()
