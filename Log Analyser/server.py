#!/usr/bin/env python3
"""
server.py — Lightweight HTTP server for the Log Analyzer dashboard.

Serves the dashboard and provides an /analyze endpoint that accepts
log file uploads, runs the C++ log_analyzer binary, and returns the
JSON report.

Usage:
    python3 server.py [--port 8080]

No pip dependencies — uses only the Python 3 standard library.
"""

import http.server
import json
import os
import signal
import subprocess
import sys
import tempfile
import time
import argparse
from pathlib import Path
from urllib.parse import parse_qs, urlparse

# ── Configuration ─────────────────────────────────────────────

BASE_DIR = Path(__file__).resolve().parent
ANALYZER_BIN = BASE_DIR / "log_analyzer"
MAX_UPLOAD_BYTES = 2 * 1024 * 1024 * 1024  # 2 GB

# MIME types for static files
MIME_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".css":  "text/css; charset=utf-8",
    ".js":   "application/javascript; charset=utf-8",
    ".json": "application/json; charset=utf-8",
    ".png":  "image/png",
    ".jpg":  "image/jpeg",
    ".jpeg": "image/jpeg",
    ".svg":  "image/svg+xml",
    ".ico":  "image/x-icon",
    ".woff": "font/woff",
    ".woff2":"font/woff2",
    ".ttf":  "font/ttf",
}


# ── Request Handler ───────────────────────────────────────────

class AnalyzerHandler(http.server.BaseHTTPRequestHandler):

    # Suppress default logging per request (we do our own)
    def log_message(self, fmt, *args):
        msg = fmt % args
        sys.stderr.write(f"  {msg}\n")

    # ── CORS headers (for dev convenience) ──
    def send_cors_headers(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_cors_headers()
        self.end_headers()

    # ── GET: static files ──
    def do_GET(self):
        path = self.path.split("?")[0]

        # Default to dashboard.html
        if path == "/" or path == "":
            path = "/dashboard.html"

        # Security: prevent directory traversal
        requested = (BASE_DIR / path.lstrip("/")).resolve()
        if not str(requested).startswith(str(BASE_DIR)):
            self.send_error(403, "Forbidden")
            return

        if not requested.is_file():
            self.send_error(404, "Not Found")
            return

        ext = requested.suffix.lower()
        mime = MIME_TYPES.get(ext, "application/octet-stream")

        try:
            data = requested.read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", mime)
            self.send_header("Content-Length", str(len(data)))
            self.send_cors_headers()
            self.send_header("Cache-Control", "no-cache")
            self.end_headers()
            self.wfile.write(data)
        except Exception as e:
            self.send_error(500, str(e))

    # ── POST /analyze: run log_analyzer on uploaded file ──
    def do_POST(self):
        path = self.path.split("?")[0]

        if path != "/analyze":
            self.send_error(404, "Not Found")
            return

        # Check that the analyzer binary exists
        if not ANALYZER_BIN.exists():
            self.send_json_error(
                500,
                "log_analyzer binary not found. "
                "Compile it first:\nclang++ -std=c++17 -O3 log_analyzer.cpp -o log_analyzer"
            )
            return

        # Get filename from query string
        query = parse_qs(urlparse(self.path).query)
        filename = query.get("filename", ["upload.log"])[0]
        filename = os.path.basename(filename)  # security: strip paths
        log_format = query.get("format", [None])[0]  # optional format override

        content_length = int(self.headers.get("Content-Length", 0))
        if content_length <= 0:
            self.send_json_error(400, "No file data received.")
            return
        if content_length > MAX_UPLOAD_BYTES:
            self.send_json_error(
                413, f"File too large ({content_length / 1024**3:.1f} GB). Max is 2 GB."
            )
            return

        # Create temp directory
        tmp_dir = BASE_DIR / ".tmp_uploads"
        tmp_dir.mkdir(exist_ok=True)

        tmp_path = str(tmp_dir / f"upload_{int(time.time())}_{filename}")
        report_path = None

        try:
            # Stream request body to temp file (64KB chunks)
            file_size_mb = content_length / (1024 * 1024)
            sys.stderr.write(
                f"  ▶ Receiving {filename} ({file_size_mb:.0f} MB)...\n"
            )

            with open(tmp_path, "wb") as f:
                remaining = content_length
                while remaining > 0:
                    chunk_size = min(remaining, 65536)
                    chunk = self.rfile.read(chunk_size)
                    if not chunk:
                        break
                    f.write(chunk)
                    remaining -= len(chunk)

            actual_size = os.path.getsize(tmp_path)
            sys.stderr.write(
                f"  ✓ Received {actual_size / 1024 / 1024:.0f} MB\n"
            )

            # Create a temp report file
            report_fd, report_path = tempfile.mkstemp(
                suffix=".json", prefix="report_", dir=str(tmp_dir)
            )
            os.close(report_fd)

            # Build analyzer command
            cmd = [str(ANALYZER_BIN), tmp_path, "-o", report_path]
            if log_format:
                # Sanitize format string (only allow alphanumeric)
                safe_format = "".join(c for c in log_format if c.isalnum() or c == '_')
                if safe_format:
                    cmd.extend(["--format", safe_format])

            # Run the analyzer
            sys.stderr.write(f"  ▶ Running log_analyzer ({' '.join(cmd)})...\n")

            t0 = time.time()
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=600,  # 10 min timeout
                cwd=str(BASE_DIR),
            )
            elapsed = time.time() - t0

            if result.returncode != 0:
                stderr_msg = result.stderr.strip() or "Unknown error"
                self.send_json_error(
                    500, f"Analyzer failed:\n{stderr_msg}"
                )
                return

            sys.stderr.write(
                f"  ✓ Analysis complete in {elapsed:.1f}s\n"
            )

            # Read the report JSON
            with open(report_path, "r") as f:
                report_data = json.load(f)

            # Send the report
            response = json.dumps(report_data).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(response)))
            self.send_cors_headers()
            self.end_headers()
            self.wfile.write(response)

        except subprocess.TimeoutExpired:
            self.send_json_error(
                504, "Analysis timed out (>10 minutes).\nThe file may be too large."
            )
        except json.JSONDecodeError:
            self.send_json_error(
                500, "Analyzer produced invalid JSON output."
            )
        except Exception as e:
            self.send_json_error(500, f"Server error: {str(e)}")
        finally:
            # Cleanup temp files
            for p in [tmp_path, report_path]:
                if p and os.path.exists(p):
                    try:
                        os.unlink(p)
                    except OSError:
                        pass

    def send_json_error(self, status, message):
        body = json.dumps({"error": message}).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_cors_headers()
        self.end_headers()
        self.wfile.write(body)


# ── Main ──────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Log Analyzer Dashboard Server")
    parser.add_argument("--port", type=int, default=8080, help="Port to listen on")
    args = parser.parse_args()

    # Create temp directory
    tmp_dir = BASE_DIR / ".tmp_uploads"
    tmp_dir.mkdir(exist_ok=True)

    server = http.server.HTTPServer(("", args.port), AnalyzerHandler)

    # Graceful shutdown
    def shutdown(sig, frame):
        sys.stderr.write("\n  Shutting down...\n")
        server.shutdown()
        # Cleanup temp dir
        import shutil
        if tmp_dir.exists():
            shutil.rmtree(tmp_dir, ignore_errors=True)
        sys.exit(0)

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    print(f"""
╔══════════════════════════════════════════════════╗
║       LOG ANALYZER — Dashboard Server            ║
╚══════════════════════════════════════════════════╝

  Dashboard : http://localhost:{args.port}
  Analyzer  : {ANALYZER_BIN}
  Max upload: {MAX_UPLOAD_BYTES // (1024**3)} GB

  Ready — upload log files through the dashboard.
  Press Ctrl+C to stop.
""")

    server.serve_forever()


if __name__ == "__main__":
    main()
