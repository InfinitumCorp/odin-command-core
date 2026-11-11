import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import type { IncomingMessage } from "node:http";
import { initialState, run } from "./engine";
import { DEFAULT_AO, checkReport, project, unproject } from "./feeds";
import { verify } from "./ledger";
import { parseCot, parseCotEvent, splitEvents } from "../server/cot";
import { FeedHub, authorized, startCotUdp } from "../server/feedHub";
import dgram from "node:dgram";
import type { State } from "./types";

const live = (): State => run(initialState(5), { type: "set-simulation", enabled: false }).state;
const at = (x: number, y: number) => unproject(DEFAULT_AO, { x, y });

describe("operating-area projection", () => {
  it("round-trips and puts the SW corner at the origin", () => {
    expect(project(DEFAULT_AO, DEFAULT_AO.originLat, DEFAULT_AO.originLon)).toEqual({ x: 0, y: 0 });
    const { lat, lon } = at(37.5, 62.25);
    const p = project(DEFAULT_AO, lat, lon);
    expect(p.x).toBeCloseTo(37.5, 6);
    expect(p.y).toBeCloseTo(62.25, 6);
  });

  it("is within 1% of great-circle distance across the area", () => {
    const a = at(0, 0);
    const b = at(100, 100);
    const R = 6371.0088;
    const rad = (d: number) => (d * Math.PI) / 180;
    const h = Math.sin(rad(b.lat - a.lat) / 2) ** 2 + Math.cos(rad(a.lat)) * Math.cos(rad(b.lat)) * Math.sin(rad(b.lon - a.lon) / 2) ** 2;
    const gc = 2 * R * Math.asin(Math.sqrt(h));
    expect(Math.abs(gc - Math.hypot(100, 100)) / gc).toBeLessThan(0.01);
  });
});

describe("checkReport", () => {
  const ok = { source: "json:t", kind: "contact", lat: 38.9, lon: -77.1, detail: "x" };
  it("accepts a minimal report", () => expect(checkReport(ok).ok).toBe(true));
  it.each([
    [{ ...ok, kind: "strike" }, /unknown kind/],
    [{ ...ok, lat: 91 }, /bad lat/],
    [{ ...ok, lon: "x" }, /bad lon/],
    [{ ...ok, confidence: 2 }, /confidence/],
    [{ ...ok, affiliation: "hostile" }, /affiliation/],
    [{ ...ok, kind: "position" }, /without callsign/],
    [{ ...ok, time: "yesterday" }, /bad time/],
    [null, /not an object/],
  ])("rejects %#", (raw, reason) => {
    const c = checkReport(raw);
    expect(c.ok).toBe(false);
    if (!c.ok) expect(c.reason).toMatch(reason);
  });
});

describe("ingest command", () => {
  it("turns reports into tracks and decision points, and hashes the raw batch onto the ledger", () => {
    const { lat, lon } = at(50, 50);
    const reports = [
      { source: "json:gw", kind: "contact", lat, lon, detail: "mover", confidence: 0.4 },
      { source: "json:gw", kind: "contact", lat: lat + 0.005, lon, detail: "mover again", confidence: 0.4 },
    ];
    const s = run(live(), { type: "ingest", via: "http-json", reports }).state;
    expect(s.tracks).toHaveLength(1);
    expect(s.tracks[0].confidence).toBeCloseTo(0.64);
    expect(s.decisions.some((d) => d.kind === "unknown-contact" && d.trackId === s.tracks[0].id)).toBe(true);
    const entry = s.ledger.find((e) => e.action === "feed.ingested")!;
    expect(entry.payload).toMatchObject({ via: "http-json", accepted: 2, rejected: 0, sources: ["json:gw"] });
    expect(entry.payload.digest).toMatch(/^[0-9a-f]{64}$/);
    expect(s.feeds["json:gw"]).toMatchObject({ accepted: 2, rejected: 0 });
    expect(verify(s.ledger).ok).toBe(true);
  });

  it("moves an own asset on a position report and on a friendly contact with its callsign", () => {
    const p1 = at(12, 34);
    const p2 = at(20, 30);
    const s = run(live(), {
      type: "ingest",
      via: "test",
      reports: [
        { source: "json:gw", kind: "position", callsign: "SLUG-1", ...p1, detail: "pos" },
        { source: "cot:udp", kind: "contact", affiliation: "friendly", callsign: "HRVST-ALPHA", ...p2, detail: "pos" },
      ],
    }).state;
    const slug = s.assets.find((a) => a.callsign === "SLUG-1")!;
    expect(slug.pos.x).toBeCloseTo(12, 6);
    expect(slug.pos.y).toBeCloseTo(34, 6);
    expect(s.assets.find((a) => a.callsign === "HRVST-ALPHA")!.pos.x).toBeCloseTo(20, 6);
    expect(s.tracks).toHaveLength(0); // own assets are not contacts
  });

  it("counts rejections per source, including out-of-area and unknown callsigns", () => {
    const s = run(live(), {
      type: "ingest",
      via: "test",
      reports: [
        { source: "json:gw", kind: "contact", lat: 10, lon: 10, detail: "far away" },
        { source: "json:gw", kind: "position", callsign: "NOBODY", ...at(5, 5), detail: "pos" },
        { source: "json:gw", kind: "teleport", lat: 0, lon: 0, detail: "" },
      ],
      adapterRejected: [{ reason: "unsupported CoT type b-t-f" }],
    }).state;
    expect(s.feeds["json:gw"]).toMatchObject({ accepted: 0, rejected: 3 });
    expect(s.feeds.test).toMatchObject({ rejected: 1, lastRejection: "adapter: unsupported CoT type b-t-f" });
    expect(s.ledger.at(-1)?.payload).toMatchObject({ accepted: 0, rejected: 4 });
    expect(s.observations).toHaveLength(0);
  });

  it("silences the simulator but keeps acting on tasks when it is off", () => {
    const s = run(live(), { type: "tick", minutes: 300 }).state;
    expect(s.observations).toHaveLength(0);
    expect(s.ledger.at(-1)?.action).toBe("simulation.toggled");
  });
});

describe("CoT adapter", () => {
  const xml = readFileSync(new URL("../../samples/cot-events.xml", import.meta.url), "utf8");

  it("splits events even though each holds a self-closing <point/>", () => {
    expect(splitEvents(xml)).toHaveLength(6);
  });

  it("maps the sample events and rejects the unsupported one", () => {
    const { reports, rejected } = parseCot(xml, "cot:test");
    expect(reports.map((r) => r.kind)).toEqual(["contact", "contact", "contact", "contact", "casevac-request"]);
    expect(rejected).toEqual([{ reason: "unsupported CoT type b-t-f", uid: "chat-1" }]);
    const [bravo, unknown, bus, allied] = reports;
    expect(bravo).toMatchObject({ affiliation: "friendly", callsign: "HRVST-BRAVO", confidence: 0.85, sourceRef: "ANDROID-hrv-b" });
    expect(unknown).toMatchObject({ affiliation: "unknown", confidence: 0.55 });
    expect(unknown.detail).toContain("2 returns & slow"); // entities decoded
    expect(bus).toMatchObject({ affiliation: "neutral", callsign: "School bus 3" });
    expect(allied).toMatchObject({ affiliation: "friendly", callsign: "ALLIED-2" });
  });

  it("marks hostile-typed events as unknown with a visible note", () => {
    const r = parseCotEvent('<event uid="h1" type="a-h-G" how="h-e"><point lat="38.9" lon="-77" ce="50"/></event>', "cot:t");
    expect(r.ok && r.report).toMatchObject({ kind: "contact", affiliation: "unknown" });
    expect(r.ok && r.report.detail).toMatch(/reported hostile/);
  });

  it("end to end: the sample moves BRAVO, settles the allied patrol as friendly, and raises a casevac", () => {
    const { reports, rejected } = parseCot(xml, "cot:test");
    const s = run(live(), { type: "ingest", via: "http-cot", reports, adapterRejected: rejected }).state;
    const bravo = s.assets.find((a) => a.callsign === "HRVST-BRAVO")!.pos;
    const expected = project(DEFAULT_AO, 38.808, -76.705);
    expect(bravo.x).toBeCloseTo(expected.x, 6);
    expect(bravo.y).toBeCloseTo(expected.y, 6);
    expect(s.tracks.find((t) => t.affiliation === "friendly")).toBeDefined();
    expect(s.tracks.find((t) => t.affiliation === "neutral")).toBeUndefined(); // 0.55 is not enough to settle identity
    expect(s.decisions.some((d) => d.kind === "casevac")).toBe(true);
    expect(s.feeds["cot:test"].accepted).toBe(5);
    expect(s.feeds["http-cot"].rejected).toBe(1);
  });
});

describe("JSON sample", () => {
  it("accepts the five valid lines and rejects the two invalid ones", () => {
    const lines = readFileSync(new URL("../../samples/patrol.jsonl", import.meta.url), "utf8")
      .split(/\r?\n/)
      .filter((l) => l.trim() && !l.startsWith("//"))
      .map((l) => JSON.parse(l));
    const s = run(live(), { type: "ingest", via: "http-json", reports: lines }).state;
    expect(s.feeds["json:hrvst-gw"]).toMatchObject({ accepted: 4, rejected: 2 });
    expect(s.feeds["json:aether-mesh"]).toMatchObject({ accepted: 1, rejected: 0 });
    // The two ALPHA sightings fuse into one track at 1-(0.4*0.35) = 86%, which needs a decision.
    expect(s.tracks).toHaveLength(1);
    expect(s.tracks[0].confidence).toBeCloseTo(0.86);
    expect(s.decisions.map((d) => d.kind).sort()).toEqual(["comms", "resupply", "unknown-contact"]);
  });
});

describe("feed hub", () => {
  const req = (addr: string, auth?: string) => ({ socket: { remoteAddress: addr }, headers: auth ? { authorization: auth } : {} }) as unknown as IncomingMessage;

  it("allows loopback only when no token is configured", () => {
    expect(authorized(req("127.0.0.1"), undefined)).toBe(true);
    expect(authorized(req("::1"), undefined)).toBe(true);
    expect(authorized(req("10.0.0.7"), undefined)).toBe(false);
  });

  it("requires the bearer token when one is configured, even from loopback", () => {
    expect(authorized(req("127.0.0.1"), "s3cret")).toBe(false);
    expect(authorized(req("10.0.0.7", "Bearer s3cret"), "s3cret")).toBe(true);
    expect(authorized(req("10.0.0.7", "Bearer wrong"), "s3cret")).toBe(false);
  });

  it("queues batches and drains them exactly once", () => {
    const hub = new FeedHub();
    hub.pushJson({ reports: [{ a: 1 }] });
    hub.pushCot('<event uid="u" type="a-n-G"><point lat="38.9" lon="-77"/></event>', "http-cot", "cot:t");
    const first = hub.drain();
    expect(first.batches.map((b) => b.via)).toEqual(["http-json", "http-cot"]);
    expect(hub.drain().batches).toHaveLength(0);
  });

  it("receives CoT over a real UDP socket", async () => {
    const hub = new FeedHub();
    const sock = startCotUdp(hub, 0, "127.0.0.1");
    await new Promise((r) => sock.once("listening", r));
    const { port } = sock.address();
    const client = dgram.createSocket("udp4");
    await new Promise<void>((res, rej) =>
      client.send('<event uid="u1" type="a-u-G"><point lat="38.9" lon="-77" ce="50"/></event>', port, "127.0.0.1", (e) => (e ? rej(e) : res())),
    );
    await new Promise((r) => setTimeout(r, 150)); // loopback delivery is near-instant
    const { batches } = hub.drain();
    client.close();
    sock.close();
    expect(batches).toHaveLength(1);
    expect(batches[0]).toMatchObject({ via: "udp-cot", reports: [{ source: "cot:udp", sourceRef: "u1", kind: "contact" }] });
  });

  it("rejects a JSON body that is not a report list", () => {
    expect(() => new FeedHub().pushJson({ foo: 1 })).toThrow(/expected an array/);
  });
});
