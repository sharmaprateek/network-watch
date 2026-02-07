# Contributing

## Dev setup

We recommend using Docker for consistent tooling.

### Run locally

```bash
cp .env.example .env
# edit NW_SUBNET + NW_INTERFACE

docker compose up --build
```

### Run tests

```bash
python -m pip install -e .[test]
pytest
```

## Safety

Keep scans LAN-only and avoid adding any exploit/vulnerability code.
