FROM python:3.12-slim
WORKDIR /app
COPY soclab /app/soclab
COPY config /app/config
RUN useradd -u 10001 -m soclab && mkdir /app/data && chown 10001:10001 /app/data
USER 10001:10001
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 SOC_BIND=0.0.0.0
ENTRYPOINT ["python", "-m", "soclab"]
