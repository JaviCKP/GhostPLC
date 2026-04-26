# GhostPLC Atlas

GhostPLC Atlas is an OT honeypot MVP with two deployable pieces:

- `ghostplc-sensor`: a Python collector/API intended to run on a Linux VM next to Conpot and Cowrie.
- `ghostplc-dashboard`: a Next.js dashboard intended to run on Vercel and read anonymized events from the sensor API.

The sensor captures and normalizes honeypot activity. The dashboard renders the live operational view without storing secrets or raw runtime data in the frontend repository.

## Repository layout

```text
.
├── GHOSTPLC_ATLAS_MVP.md
├── ghostplc-dashboard/
└── ghostplc-sensor/
```

## Quick start

### Sensor

```bash
cd ghostplc-sensor
cp .env.example .env
docker compose up -d
python -m venv .venv
. .venv/bin/activate
pip install -r collector/requirements.txt
python -m collector.collector
uvicorn collector.api:app --host 0.0.0.0 --port 8088
```

### Dashboard

```bash
cd ghostplc-dashboard
cp .env.example .env.local
npm ci
npm run dev
```

Open `http://localhost:3000`.

## Environment

Sensor variables live in `ghostplc-sensor/.env.example`.
Dashboard variables live in `ghostplc-dashboard/.env.example`.

Never commit real `.env` files, API tokens, SQLite databases, GeoIP databases, private keys, generated builds, or captured runtime data.

## Deployment

Recommended MVP deployment:

- Sensor: Ubuntu VM on Google Cloud Compute Engine.
- Dashboard: Vercel project connected to `ghostplc-dashboard`.

See `GHOSTPLC_ATLAS_MVP.md` for the full deployment notes, firewall guidance, systemd units, and operational checklist.

## Tests

```bash
cd ghostplc-sensor
python -m pytest
```

```bash
cd ghostplc-dashboard
npm run lint
npm run build
```

