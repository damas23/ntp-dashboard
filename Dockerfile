FROM python:3.11-slim-bookworm

# chronyc must match the host's chronyd (Debian 12 ships chrony 4.3 on both).
RUN apt-get update \
 && apt-get install -y --no-install-recommends chrony tzdata \
 && rm -rf /var/lib/apt/lists/*

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY ticc-dash.py .
COPY templates ./templates
COPY static ./static

# Numeric IDs of the host's _chrony user: only root or that user may run
# "chronyc clients". The UID/GID are set in docker-compose.yml.
EXPOSE 5000

CMD ["gunicorn", "--workers", "3", "--threads", "4", \
     "--bind", "0.0.0.0:5000", "--no-control-socket", \
     "--worker-tmp-dir", "/dev/shm", "--access-logfile", "-", \
     "ticc-dash:app"]
