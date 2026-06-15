FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    STATE_FILE=/data/state.json \
    TZ=Europe/Bucharest

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY anc_watch.py .

# unprivileged runtime user; /data is the (volume-mounted) state dir
RUN useradd --create-home --uid 1000 app \
    && mkdir -p /data \
    && chown -R app:app /data /app
USER app

VOLUME ["/data"]

# default: long-running watcher (loops every CHECK_INTERVAL seconds)
ENTRYPOINT ["python", "anc_watch.py"]
CMD ["--loop"]
