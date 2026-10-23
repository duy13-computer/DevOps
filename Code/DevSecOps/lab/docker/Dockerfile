FROM python:3.12-alpine AS builder
WORKDIR /build
COPY src/app/requirements-fixed.txt ./requirements.txt
RUN pip wheel --no-cache-dir --wheel-dir=/wheels -r requirements.txt

FROM python:3.12-alpine AS runtime
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
RUN apk upgrade --no-cache
COPY --from=builder /wheels /wheels
COPY src/app/requirements-fixed.txt ./requirements.txt
RUN pip install --no-cache-dir --no-index --find-links=/wheels -r requirements.txt \
    && rm -rf /wheels \
    && addgroup -S -g 10001 app \
    && adduser -S -u 10001 -G app -h /app app
COPY --chown=10001:10001 src/app/app.py ./app.py
EXPOSE 5000
USER 10001:10001
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD python -c "from urllib.request import urlopen; urlopen('http://127.0.0.1:5000/health', timeout=2)"
CMD ["python", "app.py"]
