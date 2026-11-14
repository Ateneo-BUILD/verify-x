"""Gunicorn configuration file."""

import multiprocessing
import os

# Bind to localhost — Nginx handles external connections
bind = "127.0.0.1:8000"

# Workers: 2 * CPU cores + 1
workers = multiprocessing.cpu_count() * 2 + 1

# Worker class. Threads from GUNICORN_THREADS in the site's .env (the unit's
# EnvironmentFile), 2 when it is unset; the app reads the same variable for
# the most threads that may wait for a signer that polls (verify/settings.py,
# SIGNER_QUEUE_MAX_WAITING).
worker_class = "gthread"
threads = int(os.environ.get("GUNICORN_THREADS") or 2)

# Logging
accesslog = "/var/log/gunicorn/access.log"
errorlog = "/var/log/gunicorn/error.log"
loglevel = "info"

# Process naming
proc_name = "verify"

# Timeout
timeout = 120
graceful_timeout = 30

# Restart workers after this many requests (prevents memory leaks)
max_requests = 1000
max_requests_jitter = 50

# Capture Django/app print and logging output
capture_output = True
