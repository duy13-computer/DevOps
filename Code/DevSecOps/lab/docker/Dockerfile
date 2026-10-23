# Compatibility copy of Dockerfile.vuln for the existing lab helper scripts.
FROM python:3.6-slim
WORKDIR /app
USER root
RUN apt-get update && apt-get install -y curl wget git vim
COPY src/app/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt
ADD . /app
# SEEDED-DOCKER-03: fake marker file is copied into the image layer.
COPY lab/docker/dummy-secret.txt /app/dummy-secret.txt
EXPOSE 5000
CMD ["python", "src/app/app.py"]
