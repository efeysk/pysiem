FROM python:3.12-slim

LABEL maintainer="PySIEM Team"
LABEL description="PySIEM"

RUN groupadd -r pysiem && useradd -r -g pysiem -d /app pysiem

WORKDIR /app

COPY pyproject.toml .
COPY src/ src/
COPY main.py .
COPY rules/ rules/
COPY data/ data/

RUN pip install --no-cache-dir -e .

RUN chown -R pysiem:pysiem /app

USER pysiem

VOLUME ["/app/data", "/app/reports"]

ENTRYPOINT ["python", "main.py"]
CMD ["--help"]
