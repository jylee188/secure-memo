FROM python:3.12-slim

ARG BUILD_VERSION=local

ENV BUILD_VERSION=${BUILD_VERSION}
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

RUN groupadd --system appgroup \
    && useradd --system --gid appgroup appuser

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

COPY --chown=appuser:appgroup app.py .
COPY --chown=appuser:appgroup static ./static

USER appuser

EXPOSE 8000

CMD ["sh", "-c", "python -c 'from app import init_db; init_db()' && exec gunicorn --workers 2 --threads 2 --bind 0.0.0.0:8000 --access-logfile - --error-logfile - app:app"]