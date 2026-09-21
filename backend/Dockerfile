# Build from the repo root:  docker build -f backend/Dockerfile .   (docker-compose.yml does this)
FROM python:3.12-slim
WORKDIR /app
ENV PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1

# Dependencies first, so editing code doesn't re-download TensorFlow.
COPY requirements.txt ./requirements.txt
COPY backend/requirements.txt ./backend/requirements.txt
RUN pip install -r requirements.txt -r backend/requirements.txt

COPY cyber_ai ./cyber_ai
COPY backend ./backend
COPY artifacts ./artifacts
COPY configs ./configs
COPY demo ./demo
COPY data ./data
COPY reports ./reports

RUN useradd -m app && chown -R app /app
USER app

# The committed models were saved on Windows, where Keras 2.18 wrote backslash-named groups into the weights file;
# Linux cannot find them ("expected 3 variables, but received 0"). Rewrite them to portable "/" paths (weights are
# copied unchanged; see the script's docstring). Done here so the image ships loadable models, and again at start
# (below) so a model trained on Windows and copied into the artifacts volume works too. Idempotent.
RUN python backend/scripts/make_keras_portable.py artifacts/models

EXPOSE 8000
# One worker on purpose: see "Running with multiple workers" in README.md before raising it.
HEALTHCHECK --interval=30s --timeout=5s --start-period=90s \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/api/health')"
CMD ["sh", "-c", "python backend/scripts/make_keras_portable.py artifacts/models && exec uvicorn app.main:app --host 0.0.0.0 --port 8000 --app-dir backend"]
