# syntax=docker/dockerfile:1
FROM python:3.12-slim AS builder

WORKDIR /build
COPY fb.py .
COPY tests ./tests

RUN python -m pip install --no-cache-dir pytest \
    && python -m pytest -q \
    && python -m compileall -q fb.py tests

FROM python:3.12-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1
WORKDIR /app

COPY --from=builder /build/fb.py ./fb.py

RUN addgroup --system app && adduser --system --ingroup app app
USER app

ENTRYPOINT ["python", "/app/fb.py"]
