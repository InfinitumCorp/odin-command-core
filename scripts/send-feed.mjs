#!/usr/bin/env node
// Replays a sample feed into a running ODIN° console, one item every --interval ms.
//
//   node scripts/send-feed.mjs samples/patrol.jsonl              JSON reports, one per line
//   node scripts/send-feed.mjs samples/cot-events.xml            CoT <event> elements
//   node scripts/send-feed.mjs samples/cot-events.xml --udp 4242 send CoT over UDP instead
//
// Options: --url http://localhost:5317  --interval 1500  --feed <name>  --token <bearer>
//          (token defaults to $ODIN_FEED_TOKEN)

import { readFileSync } from "node:fs";
import dgram from "node:dgram";

const args = process.argv.slice(2);
// The first argument that is neither an option nor an option's value.
const file = args.find((a, i) => !a.startsWith("--") && !(i > 0 && args[i - 1].startsWith("--")));
const opt = (name, dflt) => {
  const i = args.indexOf(`--${name}`);
  return i >= 0 ? args[i + 1] : dflt;
};
if (!file) {
  console.error("usage: node scripts/send-feed.mjs <file.jsonl|file.xml> [--url URL] [--interval MS] [--feed NAME] [--udp PORT]");
  process.exit(2);
}
const url = opt("url", "http://localhost:5317");
const interval = Number(opt("interval", "1500"));
const feed = opt("feed", "replay");
const token = opt("token", process.env.ODIN_FEED_TOKEN);
const udpPort = Number(opt("udp", "0"));
const text = readFileSync(file, "utf8");
const isCot = file.endsWith(".xml");
const items = isCot
  ? text.match(/<event\b[\s\S]*?<\/event>/gi) ?? []
  : text.split(/\r?\n/).filter((l) => l.trim() && !l.trim().startsWith("//")).map((l) => JSON.parse(l));

const headers = { "x-odin-feed": feed, ...(token ? { authorization: `Bearer ${token}` } : {}) };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const udp = udpPort ? dgram.createSocket("udp4") : undefined;

for (const [i, item] of items.entries()) {
  if (udp) {
    await new Promise((res, rej) => udp.send(Buffer.from(item), udpPort, "127.0.0.1", (e) => (e ? rej(e) : res())));
    console.log(`[${i + 1}/${items.length}] udp:${udpPort} sent`);
  } else {
    const res = await fetch(`${url}/api/feeds/${isCot ? "cot" : "json"}`, {
      method: "POST",
      headers: { ...headers, "content-type": isCot ? "application/xml" : "application/json" },
      body: isCot ? item : JSON.stringify({ reports: [item] }),
    });
    console.log(`[${i + 1}/${items.length}] ${res.status} ${await res.text()}`);
    if (!res.ok) process.exitCode = 1;
  }
  if (i < items.length - 1) await sleep(interval);
}
udp?.close();
