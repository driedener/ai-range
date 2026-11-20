FROM python:3.12-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/*

COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt

# Dedicated user: the bundled Claude CLI needs a writable HOME
RUN useradd -m -u 1000 agent
USER agent
WORKDIR /app
ENV PYTHONUNBUFFERED=1 PYTHONPATH=/app

ENTRYPOINT ["python", "-m", "airange"]
CMD ["--help"]
