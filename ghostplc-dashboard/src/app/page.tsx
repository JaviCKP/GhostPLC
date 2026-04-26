"use client";

import dynamic from "next/dynamic";
import {
  Activity,
  Clock3,
  RadioTower,
  RefreshCw,
  Server,
  ShieldAlert,
  Terminal,
  Zap,
} from "lucide-react";
import type { GlobeMethods } from "react-globe.gl";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { CyberPanel } from "@/components/CyberPanel";

const Globe = dynamic(() => import("react-globe.gl"), { ssr: false });

type AttackEvent = {
  ts: string;
  src_ip_hash: string;
  country: string;
  country_code: string;
  lat: number;
  lon: number;
  geo_source?: "demo" | "maxmind";
  protocol: string;
  port: number;
  event_type: string;
  honeypot: string;
  severity: "low" | "medium" | "high" | string;
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

type EventsPayload = {
  events: AttackEvent[];
  analysis: SensorAnalysis | null;
  source: "live" | "unconfigured" | "error";
  error?: string;
  updatedAt: string;
};

type AttackStyle = {
  label: string;
  shortLabel: string;
  color: string;
};

type ArcDatum = {
  startLat: number;
  startLng: number;
  endLat: number;
  endLng: number;
  color: string;
  label: string;
};

type PointDatum = {
  lat: number;
  lng: number;
  label: string;
  color: string;
  kind: "plant" | "event";
};

type RingDatum = {
  lat: number;
  lng: number;
  color: string;
};

type AnimatedAttack = AttackEvent & {
  animationKey: string;
  expiresAt: number;
};

type GlobeControls = {
  enableDamping: boolean;
  dampingFactor: number;
  rotateSpeed: number;
  zoomSpeed: number;
  enablePan: boolean;
  mouseButtons: {
    LEFT: number;
    MIDDLE: number;
    RIGHT: number;
  };
  touches: {
    ONE: number;
    TWO: number;
  };
};

const PLANT = {
  lat: 40.4168,
  lng: -3.7038,
  label: "GhostPLC Madrid",
};

const ORBIT_MOUSE = {
  ROTATE: 0,
  DOLLY: 1,
} as const;

const ORBIT_TOUCH = {
  ROTATE: 0,
  DOLLY_PAN: 2,
} as const;

const ARC_ANIMATE_TIME = 1450;
const ARC_ITERATIONS = 3;
const ARC_LIFETIME_MS = ARC_ANIMATE_TIME * ARC_ITERATIONS + 180;
const MAX_NEW_ANIMATIONS_PER_POLL = 24;

const ATTACK_STYLES: Record<string, AttackStyle> = {
  modbus_probe: { label: "Modbus probe", shortLabel: "Modbus", color: "#fb923c" },
  s7_probe: { label: "S7 probe", shortLabel: "S7", color: "#38bdf8" },
  snmp_probe: { label: "SNMP sweep", shortLabel: "SNMP", color: "#a3e635" },
  industrial_http_probe: { label: "HTTP industrial", shortLabel: "HTTP", color: "#facc15" },
  ics_probe: { label: "ICS probe", shortLabel: "ICS", color: "#22c55e" },
  ssh_login_attempt: { label: "SSH login", shortLabel: "SSH login", color: "#f43f5e" },
  ssh_probe: { label: "SSH probe", shortLabel: "SSH", color: "#fb7185" },
  ssh_activity: { label: "SSH activity", shortLabel: "SSH", color: "#e879f9" },
  unknown_probe: { label: "Unknown probe", shortLabel: "Unknown", color: "#cbd5e1" },
};

const PROTOCOL_FALLBACKS: Record<string, AttackStyle> = {
  modbus: ATTACK_STYLES.modbus_probe,
  s7: ATTACK_STYLES.s7_probe,
  s7comm: ATTACK_STYLES.s7_probe,
  snmp: ATTACK_STYLES.snmp_probe,
  http: ATTACK_STYLES.industrial_http_probe,
  ics: ATTACK_STYLES.ics_probe,
  ssh: ATTACK_STYLES.ssh_probe,
};

const DEFAULT_ATTACK_STYLE: AttackStyle = {
  label: "Unknown probe",
  shortLabel: "Unknown",
  color: "#cbd5e1",
};

const VIEW_FILTERS = [
  { id: "all", label: "todo" },
  { id: "ot", label: "OT" },
  { id: "ssh", label: "SSH" },
  { id: "modbus", label: "Modbus" },
  { id: "s7", label: "S7" },
  { id: "snmp", label: "SNMP" },
];

const OT_PROTOCOLS = new Set(["modbus", "s7", "s7comm", "snmp", "ics", "http"]);
const LEGEND_FALLBACK = [
  ATTACK_STYLES.modbus_probe,
  ATTACK_STYLES.s7_probe,
  ATTACK_STYLES.snmp_probe,
  ATTACK_STYLES.ssh_login_attempt,
  ATTACK_STYLES.industrial_http_probe,
];

function countBy<T extends string>(items: AttackEvent[], selector: (item: AttackEvent) => T) {
  return Object.entries(
    items.reduce<Record<string, number>>((acc, item) => {
      const key = selector(item);
      acc[key] = (acc[key] || 0) + 1;
      return acc;
    }, {}),
  ).sort((a, b) => b[1] - a[1]);
}

function eventAttackStyle(event: Pick<AttackEvent, "event_type" | "protocol">): AttackStyle {
  return ATTACK_STYLES[event.event_type] || PROTOCOL_FALLBACKS[event.protocol] || DEFAULT_ATTACK_STYLE;
}

function attackStyleFromKey(key: string): AttackStyle {
  return ATTACK_STYLES[key] || {
    ...DEFAULT_ATTACK_STYLE,
    label: key.replaceAll("_", " "),
    shortLabel: key.replaceAll("_", " "),
  };
}

function matchesView(event: Pick<AttackEvent, "protocol">, view: string) {
  if (view === "all") {
    return true;
  }
  if (view === "ot") {
    return OT_PROTOCOLS.has(event.protocol);
  }
  if (view === "ssh") {
    return event.protocol === "ssh";
  }
  if (view === "s7") {
    return event.protocol === "s7" || event.protocol === "s7comm";
  }
  return event.protocol === view;
}

function timeLabel(value: string) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return "--:--:--";
  }

  return date.toLocaleTimeString("es-ES", {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

function ageLabel(value: string | undefined, now: number) {
  if (!value || !now) {
    return "pendiente";
  }

  const timestamp = new Date(value).getTime();
  if (Number.isNaN(timestamp)) {
    return "pendiente";
  }

  const seconds = Math.max(0, Math.floor((now - timestamp) / 1000));
  if (seconds < 90) {
    return `${seconds}s`;
  }
  const minutes = Math.floor(seconds / 60);
  if (minutes < 90) {
    return `${minutes}m`;
  }
  return `${Math.floor(minutes / 60)}h`;
}

function sourceLabel(source: EventsPayload["source"], error?: string) {
  if (source === "live") {
    return "sensor conectado";
  }
  if (source === "unconfigured") {
    return "sensor sin configurar";
  }
  return error || "sensor no disponible";
}

function eventTimestamp(event: AttackEvent) {
  const timestamp = new Date(event.ts).getTime();
  return Number.isNaN(timestamp) ? 0 : timestamp;
}

function percent(part: number, total: number) {
  if (!total) {
    return 0;
  }
  return Math.round((part / total) * 100);
}

function splitNarrative(text?: string) {
  return (text || "")
    .split(/\n+/)
    .map((line) => line.trim())
    .filter(Boolean);
}

function eventAnimationKey(event: AttackEvent) {
  return `${event.ts}|${event.src_ip_hash}|${event.event_type}|${event.protocol}|${event.port}`;
}

export default function Home() {
  const globeRef = useRef<GlobeMethods | undefined>(undefined);
  const seenAnimationKeysRef = useRef<Set<string>>(new Set());
  const [events, setEvents] = useState<AttackEvent[]>([]);
  const [activeAnimations, setActiveAnimations] = useState<AnimatedAttack[]>([]);
  const [analysis, setAnalysis] = useState<SensorAnalysis | null>(null);
  const [source, setSource] = useState<EventsPayload["source"]>("unconfigured");
  const [error, setError] = useState<string | undefined>();
  const [updatedAt, setUpdatedAt] = useState<string>("");
  const [activeView, setActiveView] = useState("all");
  const [isLoading, setIsLoading] = useState(false);
  const [viewport, setViewport] = useState({ width: 1200, height: 800 });
  const [now, setNow] = useState(0);

  const loadEvents = useCallback(async () => {
    setIsLoading(true);
    try {
      const res = await fetch("/api/events", { cache: "no-store" });
      const payload = (await res.json()) as EventsPayload;
      const nextEvents = payload.events.slice(-700);
      const loadedAt = Date.now();
      const newAnimations = nextEvents
        .slice(-MAX_NEW_ANIMATIONS_PER_POLL)
        .map((event) => ({
          event,
          key: eventAnimationKey(event),
        }))
        .filter(({ key }) => !seenAnimationKeysRef.current.has(key))
        .map(({ event, key }) => {
          seenAnimationKeysRef.current.add(key);
          return {
            ...event,
            animationKey: key,
            expiresAt: loadedAt + ARC_LIFETIME_MS,
          };
        });

      setEvents(nextEvents);
      if (newAnimations.length) {
        setActiveAnimations((current) => [
          ...current.filter((event) => event.expiresAt > loadedAt),
          ...newAnimations,
        ]);
      } else {
        setActiveAnimations((current) => current.filter((event) => event.expiresAt > loadedAt));
      }
      setAnalysis(payload.analysis || null);
      setSource(payload.source);
      setError(payload.error);
      setUpdatedAt(payload.updatedAt);
      setNow(loadedAt);
    } catch (requestError) {
      setSource("error");
      setError(requestError instanceof Error ? requestError.message : "error desconocido");
      setUpdatedAt(new Date().toISOString());
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    const initialLoad = window.setTimeout(() => {
      void loadEvents();
    }, 0);
    const timer = window.setInterval(() => {
      void loadEvents();
    }, 5000);

    return () => {
      window.clearTimeout(initialLoad);
      window.clearInterval(timer);
    };
  }, [loadEvents]);

  useEffect(() => {
    function resize() {
      setViewport({ width: window.innerWidth, height: window.innerHeight });
    }

    const frame = window.requestAnimationFrame(resize);
    window.addEventListener("resize", resize);
    return () => {
      window.cancelAnimationFrame(frame);
      window.removeEventListener("resize", resize);
    };
  }, []);

  useEffect(() => {
    function tick() {
      setNow(Date.now());
    }

    tick();
    const timer = window.setInterval(tick, 30000);
    return () => window.clearInterval(timer);
  }, []);

  useEffect(() => {
    const timer = window.setInterval(() => {
      const currentTime = Date.now();
      setActiveAnimations((current) => current.filter((event) => event.expiresAt > currentTime));
    }, 500);

    return () => window.clearInterval(timer);
  }, []);

  useEffect(() => {
    let frame = 0;
    let attempts = 0;

    function configureControls() {
      attempts += 1;
      const controls = globeRef.current?.controls?.() as unknown as GlobeControls | undefined;
      if (!controls) {
        if (attempts < 120) {
          frame = window.requestAnimationFrame(configureControls);
        }
        return;
      }

      controls.enableDamping = true;
      controls.dampingFactor = 0.08;
      controls.rotateSpeed = 0.72;
      controls.zoomSpeed = 0.75;
      controls.enablePan = false;
      controls.mouseButtons = {
        LEFT: ORBIT_MOUSE.ROTATE,
        MIDDLE: ORBIT_MOUSE.DOLLY,
        RIGHT: ORBIT_MOUSE.ROTATE,
      };
      controls.touches = {
        ONE: ORBIT_TOUCH.ROTATE,
        TWO: ORBIT_TOUCH.DOLLY_PAN,
      };
    }

    frame = window.requestAnimationFrame(configureControls);
    return () => window.cancelAnimationFrame(frame);
  }, []);

  const filteredEvents = useMemo(
    () => events.filter((event) => matchesView(event, activeView)),
    [activeView, events],
  );
  const visibleAnimations = useMemo(
    () => activeAnimations.filter((event) => matchesView(event, activeView)),
    [activeAnimations, activeView],
  );

  const arcs = useMemo<ArcDatum[]>(
    () =>
      visibleAnimations.map((event) => {
        const style = eventAttackStyle(event);
        return {
          startLat: event.lat,
          startLng: event.lon,
          endLat: PLANT.lat,
          endLng: PLANT.lng,
          color: style.color,
          label: `${event.country} -> Espana`,
        };
      }),
    [visibleAnimations],
  );

  const points = useMemo<PointDatum[]>(
    () => [
      {
        lat: PLANT.lat,
        lng: PLANT.lng,
        label: PLANT.label,
        color: "#ffffff",
        kind: "plant",
      },
      ...filteredEvents.map((event) => {
        const style = eventAttackStyle(event);
        return {
          lat: event.lat,
          lng: event.lon,
          label: `${event.country} - ${style.label} - ${event.protocol}:${event.port}`,
          color: style.color,
          kind: "event" as const,
        };
      }),
    ],
    [filteredEvents],
  );

  const rings = useMemo<RingDatum[]>(
    () =>
      visibleAnimations.map((event) => ({
        lat: event.lat,
        lng: event.lon,
        color: eventAttackStyle(event).color,
      })),
    [visibleAnimations],
  );

  const attackStats = useMemo(
    () =>
      countBy(events, (event) => event.event_type || event.protocol || "unknown")
        .slice(0, 6)
        .map(([key, count]) => ({
          key,
          count,
          style: attackStyleFromKey(key),
        })),
    [events],
  );
  const legendItems = attackStats.length
    ? attackStats.slice(0, 5).map((item) => item.style)
    : LEGEND_FALLBACK;
  const latestEvents = filteredEvents.slice(-12).reverse();
  const otEvents = events.filter((event) => OT_PROTOCOLS.has(event.protocol)).length;
  const lastHourEvents = now
    ? events.filter((event) => now - eventTimestamp(event) <= 60 * 60 * 1000).length
    : 0;
  const countriesSeen = new Set(events.map((event) => event.country)).size;
  const usesDemoGeo = events.some((event) => event.geo_source === "demo");
  const signalScore = events.length
    ? Math.min(99, 30 + percent(otEvents, events.length) + Math.min(30, lastHourEvents))
    : 0;
  const narrative = splitNarrative(analysis?.summary);

  return (
    <main
      className="relative min-h-screen select-none overflow-x-hidden bg-[#040706] text-zinc-50"
      onContextMenu={(event) => event.preventDefault()}
    >
      <div className="fixed inset-0">
        <Globe
          ref={globeRef}
          width={viewport.width}
          height={viewport.height}
          globeImageUrl="https://cdn.jsdelivr.net/npm/three-globe/example/img/earth-blue-marble.jpg"
          backgroundImageUrl="https://cdn.jsdelivr.net/npm/three-globe/example/img/night-sky.png"
          backgroundColor="rgba(0,0,0,0)"
          showAtmosphere
          atmosphereColor="#38bdf8"
          atmosphereAltitude={0.15}
          arcsData={arcs}
          arcStartLat={(datum: object) => (datum as ArcDatum).startLat}
          arcStartLng={(datum: object) => (datum as ArcDatum).startLng}
          arcEndLat={(datum: object) => (datum as ArcDatum).endLat}
          arcEndLng={(datum: object) => (datum as ArcDatum).endLng}
          arcColor={(datum: object) => (datum as ArcDatum).color}
          arcStroke={0.72}
          arcLabel={(datum: object) => (datum as ArcDatum).label}
          arcDashLength={0.32}
          arcDashGap={0.54}
          arcDashAnimateTime={ARC_ANIMATE_TIME}
          arcAltitude={0.28}
          arcsTransitionDuration={350}
          pointsData={points}
          pointLat={(datum: object) => (datum as PointDatum).lat}
          pointLng={(datum: object) => (datum as PointDatum).lng}
          pointColor={(datum: object) => (datum as PointDatum).color}
          pointAltitude={(datum: object) => ((datum as PointDatum).kind === "plant" ? 0.1 : 0.035)}
          pointRadius={(datum: object) => ((datum as PointDatum).kind === "plant" ? 0.42 : 0.2)}
          pointLabel={(datum: object) => (datum as PointDatum).label}
          pointsTransitionDuration={0}
          ringsData={rings}
          ringLat={(datum: object) => (datum as RingDatum).lat}
          ringLng={(datum: object) => (datum as RingDatum).lng}
          ringColor={(datum: object) => (datum as RingDatum).color}
          ringMaxRadius={3.8}
          ringPropagationSpeed={1.8}
          ringRepeatPeriod={ARC_ANIMATE_TIME}
        />
      </div>

      <div className="pointer-events-none fixed inset-0 bg-[linear-gradient(90deg,rgba(2,6,4,0.84),rgba(2,6,4,0.10)_43%,rgba(2,6,4,0.70)),linear-gradient(180deg,rgba(2,6,4,0.72),rgba(2,6,4,0.02)_45%,rgba(2,6,4,0.76))]" />

      <div className="pointer-events-none relative z-10 flex min-h-screen flex-col justify-between gap-4 p-3 pb-12 sm:p-4 lg:p-6 lg:pb-6">
        <header className="grid gap-4 lg:grid-cols-[340px_minmax(300px,1fr)_480px]">
          <CyberPanel variant="emerald" className="self-start p-4">
            <div className="flex items-start justify-between gap-4">
              <div>
                <p className="text-xs font-semibold text-emerald-300">GhostPLC Atlas</p>
                <h1 className="mt-1 text-2xl font-semibold text-white">Radar OT en vivo</h1>
              </div>
              <button
                aria-label="Actualizar eventos"
                title="Actualizar eventos"
                onClick={loadEvents}
                className="grid size-10 place-items-center rounded-lg border border-white/10 bg-white/[0.08] text-zinc-100 transition hover:bg-white/[0.14]"
              >
                <RefreshCw className={`size-4 ${isLoading ? "animate-spin" : ""}`} />
              </button>
            </div>

            <div className="mt-5 grid grid-cols-3 gap-2">
              <div className="rounded-lg border border-white/10 bg-white/[0.06] p-3">
                <Activity className="mb-3 size-4 text-emerald-300" />
                <div className="font-mono text-2xl text-white">{events.length}</div>
                <div className="mt-1 text-xs text-zinc-400">eventos</div>
              </div>
              <div className="rounded-lg border border-white/10 bg-white/[0.06] p-3">
                <ShieldAlert className="mb-3 size-4 text-orange-300" />
                <div className="font-mono text-2xl text-white">{percent(otEvents, events.length)}%</div>
                <div className="mt-1 text-xs text-zinc-400">OT</div>
              </div>
              <div className="rounded-lg border border-white/10 bg-white/[0.06] p-3">
                <Zap className="mb-3 size-4 text-sky-300" />
                <div className="font-mono text-2xl text-white">{lastHourEvents}</div>
                <div className="mt-1 text-xs text-zinc-400">1h</div>
              </div>
            </div>

            <div className="mt-4 flex min-w-0 items-center gap-2 text-xs text-zinc-300">
              <span
                className={`size-2 shrink-0 rounded-full ${
                  source === "live" ? "bg-emerald-400" : "bg-orange-300"
                }`}
              />
              <span className="truncate">{sourceLabel(source, error)}</span>
              {updatedAt ? <span className="ml-auto font-mono text-zinc-500">{timeLabel(updatedAt)}</span> : null}
            </div>
          </CyberPanel>

          <CyberPanel variant="emerald" className="self-start justify-self-center p-3">
            <div className="mb-2 flex items-center gap-2 px-1 text-xs text-zinc-400">
              <RadioTower className="size-3.5 text-emerald-300" />
              <span>Vista y colores por tipo de ataque</span>
            </div>
            <div className="flex flex-wrap gap-2">
              {VIEW_FILTERS.map((filter) => (
                <button
                  key={filter.id}
                  onClick={() => setActiveView(filter.id)}
                  className={`h-8 rounded-lg border px-3 text-sm font-medium transition ${
                    activeView === filter.id
                      ? "border-white/35 bg-white text-black"
                      : "border-white/10 bg-white/[0.07] text-zinc-200 hover:bg-white/[0.13]"
                  }`}
                >
                  {filter.label}
                </button>
              ))}
            </div>
            <div className="mt-3 flex flex-wrap gap-x-4 gap-y-2 px-1">
              {legendItems.map((style) => (
                <div key={`${style.label}-${style.color}`} className="flex items-center gap-2 text-xs text-zinc-300">
                  <span className="size-2.5 rounded-full" style={{ backgroundColor: style.color }} />
                  <span>{style.shortLabel}</span>
                </div>
              ))}
            </div>
          </CyberPanel>

          <CyberPanel variant="emerald" className="flex max-h-[320px] flex-col p-4 lg:max-h-[42vh] lg:self-start">
            <div className="mb-3 flex shrink-0 items-center justify-between gap-3">
              <div className="flex items-center gap-2">
                <Terminal className="size-4 text-emerald-300" />
                <h2 className="text-sm font-semibold text-zinc-100">Ghost operator</h2>
              </div>
              <span className="font-mono text-xs text-zinc-500">{analysis?.model || "standby"}</span>
            </div>

            <div className="cyber-scrollbar flex-1 overflow-y-auto pr-3">
              {narrative.length ? (
                <div className="space-y-3 font-mono text-sm leading-6 text-emerald-50/90">
                  {narrative.map((paragraph) => (
                    <p key={paragraph}>{paragraph}</p>
                  ))}
                </div>
              ) : (
                <p className="font-mono text-sm leading-6 text-zinc-400">
                  [standby] Esperando eventos suficientes para sacar tendencias. Si el sensor esta vivo,
                  en unos minutos deberia aparecer una bitacora con ritmo, origenes y protocolos.
                </p>
              )}
            </div>

            <div className="mt-4 flex shrink-0 items-center justify-between border-t border-white/10 pt-3 text-xs text-zinc-400">
              <span>analisis hace {ageLabel(analysis?.created_at, now)}</span>
              <span>{analysis?.event_count ?? 0} eventos</span>
            </div>
          </CyberPanel>
        </header>

        <footer className="grid gap-4 lg:grid-cols-[330px_1fr_540px] lg:items-end">
          <CyberPanel variant="cyan" className="p-4">
            <div className="mb-3 flex items-center gap-2">
              <Server className="size-4 text-sky-300" />
              <h2 className="text-sm font-semibold text-zinc-100">Tipos detectados</h2>
            </div>
            <div className="space-y-2">
              {attackStats.length ? (
                attackStats.slice(0, 5).map(({ key, count, style }) => (
                  <div key={key} className="grid grid-cols-[1fr_auto] items-center gap-3">
                    <div className="flex min-w-0 items-center gap-2">
                      <span className="size-2.5 shrink-0 rounded-full" style={{ backgroundColor: style.color }} />
                      <span className="truncate text-sm text-zinc-200">{style.label}</span>
                    </div>
                    <span className="font-mono text-sm text-zinc-400">{count}</span>
                  </div>
                ))
              ) : (
                <div className="text-sm text-zinc-500">Sin ataques todavia</div>
              )}
            </div>

            <div className="mt-4 grid grid-cols-3 gap-3 border-t border-white/10 pt-3 text-xs text-zinc-400">
              <div>
                <div className="font-mono text-lg text-white">{signalScore}</div>
                <div>senal</div>
              </div>
              <div>
                <div className="font-mono text-lg text-white">{countriesSeen}</div>
                <div>paises</div>
              </div>
              <div>
                <div className="font-mono text-lg text-white">{filteredEvents.length}</div>
                <div>vista</div>
              </div>
            </div>
            {usesDemoGeo ? (
              <div className="mt-3 border-t border-orange-300/20 pt-3 text-xs text-orange-100">
                GeoIP demo activo.
              </div>
            ) : null}
          </CyberPanel>

          <div className="hidden lg:block" />

          <CyberPanel variant="orange" className="flex max-h-[380px] flex-col p-4 lg:max-h-[42vh]">
            <div className="mb-3 flex items-center justify-between gap-3">
              <div className="flex items-center gap-2">
                <Clock3 className="size-4 text-orange-300" />
                <h2 className="text-sm font-semibold text-zinc-100">Ultimos eventos</h2>
              </div>
              <span className="font-mono text-xs text-zinc-500">{filteredEvents.length}</span>
            </div>
            <div className="cyber-scrollbar flex-1 space-y-1 overflow-y-auto pr-2">
              {latestEvents.length ? (
                latestEvents.map((event, index) => {
                  const style = eventAttackStyle(event);
                  return (
                    <div
                      key={`${event.ts}-${event.src_ip_hash}-${index}`}
                      className="grid grid-cols-[76px_1fr_auto] items-center gap-3 border-b border-white/8 py-2 last:border-b-0"
                    >
                      <span className="font-mono text-xs text-zinc-500">{timeLabel(event.ts)}</span>
                      <span className="min-w-0 truncate text-sm text-zinc-200">
                        {event.country} - {event.protocol}:{event.port}
                      </span>
                      <span
                        className="rounded-md border px-2 py-1 font-mono text-xs"
                        style={{
                          borderColor: `${style.color}55`,
                          backgroundColor: `${style.color}18`,
                          color: style.color,
                        }}
                      >
                        {style.shortLabel}
                      </span>
                    </div>
                  );
                })
              ) : (
                <div className="py-5 text-sm text-zinc-500">Esperando eventos del sensor</div>
              )}
            </div>
          </CyberPanel>
        </footer>
      </div>
    </main>
  );
}
