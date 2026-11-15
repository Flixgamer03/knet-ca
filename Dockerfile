FROM python:3.13-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends tzdata \
 && rm -rf /var/lib/apt/lists/* \
 && groupadd -g 1000 ca && useradd -u 1000 -g 1000 -m -d /home/ca ca \
 && mkdir -p /data && chown 1000:1000 /data
WORKDIR /opt/knet-ca
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app ./app
USER 1000:1000
ENV PYTHONUNBUFFERED=1 DATA_DIR=/data
VOLUME ["/data"]
EXPOSE 9000 8443 8080
HEALTHCHECK --interval=30s --timeout=6s --start-period=20s CMD ["python", "-m", "app.healthcheck"]
CMD ["python", "-m", "app.server"]
