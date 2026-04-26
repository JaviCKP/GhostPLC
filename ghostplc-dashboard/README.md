# GhostPLC Dashboard

Next.js dashboard for GhostPLC Atlas. It reads anonymized OT honeypot events from the sensor API and renders the live operations view.

## Setup

```bash
npm ci
cp .env.example .env.local
npm run dev
```

Open `http://localhost:3000`.

## Environment variables

```text
SENSOR_EVENTS_URL=http://YOUR_SENSOR_HOST:8088/events.json
SENSOR_ANALYSIS_URL=http://YOUR_SENSOR_HOST:8088/analysis
SENSOR_API_TOKEN=your_sensor_token
SENSOR_FETCH_TIMEOUT_MS=6000
```

Do not commit `.env.local` or any real sensor token.

## Scripts

```bash
npm run dev
npm run lint
npm run build
npm run start
```

## Deployment

Deploy this directory to Vercel. Set the same environment variables in Vercel project settings before exposing the deployment publicly.

