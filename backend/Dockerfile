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

EXPOSE 8000
# One worker on purpose: see "Running with multiple workers" in README.md before raising it.
HEALTHCHECK --interval=30s --timeout=5s --start-period=90s \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/api/health')"
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--app-dir", "backend"]
