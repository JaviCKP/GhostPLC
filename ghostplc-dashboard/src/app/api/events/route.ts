import { NextResponse } from "next/server";

export const dynamic = "force-dynamic";
const SENSOR_FETCH_TIMEOUT_MS = Number.parseInt(
  process.env.SENSOR_FETCH_TIMEOUT_MS || "6000",
  10,
);

type SensorEvent = {
  ts?: string;
  src_ip_hash?: string;
  country?: string;
  country_code?: string;
  lat?: number;
  lon?: number;
  geo_source?: string;
  protocol?: string;
  port?: number;
  event_type?: string;
  honeypot?: string;
  severity?: string;
};

type SensorAnalysis = {
  created_at?: string;
  window_start?: string;
  window_end?: string;
  model?: string;
  event_count?: number;
  title?: string;
  summary?: string;
  findings?: Array<{
    label: string;
    detail: string;
    severity: string;
  }>;
  recommendations?: string[];
};

function normalizeEvents(payload: unknown): SensorEvent[] {
  if (!Array.isArray(payload)) {
    return [];
  }

  return payload.filter((event): event is SensorEvent => {
    if (!event || typeof event !== "object") {
      return false;
    }

    const candidate = event as SensorEvent;
    return (
      typeof candidate.ts === "string" &&
      typeof candidate.country === "string" &&
      typeof candidate.lat === "number" &&
      typeof candidate.lon === "number" &&
      typeof candidate.protocol === "string"
    );
  });
}

function normalizeAnalysis(payload: unknown): SensorAnalysis | null {
  if (!payload || typeof payload !== "object") {
    return null;
  }

  const candidate = payload as SensorAnalysis;
  if (typeof candidate.summary !== "string") {
    return null;
  }

  return candidate;
}

function analysisUrlFromEventsUrl(eventsUrl: string) {
  if (process.env.SENSOR_ANALYSIS_URL) {
    return process.env.SENSOR_ANALYSIS_URL;
  }

  try {
    const url = new URL(eventsUrl);
    url.pathname = url.pathname.replace(/\/events(\.json)?$/, "/analysis");
    return url.toString();
  } catch {
    return null;
  }
}

export async function GET() {
  const url = process.env.SENSOR_EVENTS_URL;

  if (!url) {
    return NextResponse.json(
      {
        events: [],
        source: "unconfigured",
        updatedAt: new Date().toISOString(),
      },
      {
        headers: {
          "Cache-Control": "no-store",
        },
      },
    );
  }

  const headers: HeadersInit = {};
  if (process.env.SENSOR_API_TOKEN) {
    headers.Authorization = `Bearer ${process.env.SENSOR_API_TOKEN}`;
  }

  try {
    const response = await fetch(url, {
      cache: "no-store",
      headers,
      signal: AbortSignal.timeout(SENSOR_FETCH_TIMEOUT_MS),
    });

    if (!response.ok) {
      return NextResponse.json(
        {
          events: [],
          source: "error",
          error: `sensor HTTP ${response.status}`,
          updatedAt: new Date().toISOString(),
        },
        {
          headers: {
            "Cache-Control": "no-store",
          },
        },
      );
    }

    const payload = await response.json();
    let analysis: SensorAnalysis | null = null;
    const analysisUrl = analysisUrlFromEventsUrl(url);

    if (analysisUrl) {
      try {
        const analysisResponse = await fetch(analysisUrl, {
          cache: "no-store",
          headers,
          signal: AbortSignal.timeout(SENSOR_FETCH_TIMEOUT_MS),
        });
        if (analysisResponse.ok) {
          analysis = normalizeAnalysis(await analysisResponse.json());
        }
      } catch {
        analysis = null;
      }
    }

    return NextResponse.json(
      {
        events: normalizeEvents(payload).slice(-1000),
        analysis,
        source: "live",
        updatedAt: new Date().toISOString(),
      },
      {
        headers: {
          "Cache-Control": "no-store",
        },
      },
    );
  } catch (error) {
    return NextResponse.json(
      {
        events: [],
        source: "error",
        error: error instanceof Error ? error.message : "sensor fetch failed",
        updatedAt: new Date().toISOString(),
      },
      {
        headers: {
          "Cache-Control": "no-store",
        },
      },
    );
  }
}
