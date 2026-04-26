# GhostPLC Sensor

Python sensor and API for GhostPLC Atlas. The sensor is designed to run on a Linux VM alongside Conpot and Cowrie, normalize honeypot events, store them in SQLite, and expose token-protected JSON endpoints for the dashboard.

## Components

- `docker-compose.yml`: Conpot and Cowrie honeypots.
- `collector/collector.py`: event collection and normalization.
- `collector/storage.py`: SQLite persistence.
- `collector/api.py`: FastAPI endpoints.
- `collector/analyzer.py`: optional AI narrative analysis.
- `systemd/`: service and timer units.
- `scripts/`: firewall, install, redirect, and smoke-test helpers.

## Setup

```bash
cp .env.example .env
docker compose up -d
python -m venv .venv
. .venv/bin/activate
pip install -r collector/requirements.txt
```

Set a strong `GHOSTPLC_API_TOKEN` in `.env` before exposing the API.

## Run locally

```bash
python -m collector.collector
uvicorn collector.api:app --host 0.0.0.0 --port 8088
```

Useful endpoints:

```text
GET /health
GET /events.json
GET /analysis
```

`/events.json` and `/analysis` require:

```text
Authorization: Bearer YOUR_TOKEN
```

## Tests

```bash
python -m pytest
```

## Deployment notes

Use the scripts in `scripts/` and units in `systemd/` as deployment helpers for an Ubuntu VM. Review firewall exposure carefully before making the sensor public.

Do not commit `.env`, `data/`, SQLite files, GeoIP databases, private keys, generated caches, or captured logs.

