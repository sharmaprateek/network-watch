FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
  && apt-get install -y --no-install-recommends \
    python3 python3-pip python3-venv \
    curl ca-certificates \
    nmap arp-scan iproute2 iputils-ping \
    openssl \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Python deps
COPY pyproject.toml /app/pyproject.toml
COPY src /app/src
RUN python3 -m venv /venv \
  && /venv/bin/pip install --no-cache-dir -U pip \
  && /venv/bin/pip install --no-cache-dir -e .

# App code + scripts
COPY scan.sh render.py enrich.py ssdp_probe.py web_probe.py final_report.py alert.py server.sh /app/
COPY site /app/site
COPY state /app/state

# Entry
COPY docker/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh /app/scan.sh

EXPOSE 8787

ENV PATH=/venv/bin:$PATH

ENTRYPOINT ["/entrypoint.sh"]
