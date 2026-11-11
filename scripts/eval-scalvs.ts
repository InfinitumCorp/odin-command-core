// SCALVS eval runner.
//
//   npm run eval:scalvs                          Claude (needs ANTHROPIC_API_KEY), 1 attempt per case
//   npm run eval:scalvs -- --repeat 3            consistency across repeated runs
//   npm run eval:scalvs -- --drafter rules       rule-engine baseline (no API calls)
//   npm run eval:scalvs -- --only uc-01,inj-summary
//   npm run eval:scalvs -- --regrade evals/scalvs/results/<file>.json   re-score stored proposals
//   npm run eval:scalvs -- --update-digests      accept engine changes that altered the cases
//   npm run eval:scalvs -- --min-pass 0.9        exit 1 below this attempt pass rate (for CI)
//
// Results go to evals/scalvs/results/<drafter>-<time>.json (proposals included, so a run can
// be regraded later) and a Markdown report next to it.

import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { buildCase, regrade, report, rulesDrafter, runEval, type CaseResult, type EvalCase, type EvalDrafter } from "../src/eval/scalvsEval";
import { draftWithClaude, describeFailure } from "../src/server/scalvs";

const args = process.argv.slice(2);
const flag = (name: string) => args.includes(`--${name}`);
const opt = (name: string) => {
  const i = args.indexOf(`--${name}`);
  return i >= 0 ? args[i + 1] : undefined;
};

const casesPath = opt("cases") ?? "evals/scalvs/cases.json";
const outDir = opt("out") ?? "evals/scalvs/results";
let cases = JSON.parse(readFileSync(casesPath, "utf8")) as EvalCase[];

if (flag("update-digests")) {
  for (const c of cases) c.digest = buildCase(c).digest;
  writeFileSync(casesPath, JSON.stringify(cases, null, 2) + "\n");
  console.log(`updated digests for ${cases.length} cases in ${casesPath}`);
  process.exit(0);
}

const only = opt("only")?.split(",");
if (only) cases = cases.filter((c) => only.includes(c.id));
if (!cases.length) throw new Error("no cases selected");

const drafterName = opt("drafter") ?? "claude";
const drafters: Record<string, EvalDrafter> = {
  rules: rulesDrafter,
  claude: async (situation) => {
    try {
      return await draftWithClaude(situation);
    } catch (e) {
      throw new Error(describeFailure(e));
    }
  },
};

const date = new Date().toISOString();
let out: { results: CaseResult[]; summary: ReturnType<typeof regrade>["summary"] };
let meta: { drafter: string; model?: string; repeat: number; date: string };

const regradeFrom = opt("regrade");
if (regradeFrom) {
  const prev = JSON.parse(readFileSync(regradeFrom, "utf8")) as { meta: typeof meta; results: CaseResult[] };
  out = regrade(cases, prev.results);
  meta = { ...prev.meta, drafter: `${prev.meta.drafter} (regraded)`, date };
} else {
  const drafter = drafters[drafterName];
  if (!drafter) throw new Error(`unknown drafter ${drafterName} (rules, claude)`);
  const repeat = Number(opt("repeat") ?? 1);
  const concurrency = Number(opt("concurrency") ?? 3);
  console.log(`SCALVS eval · ${cases.length} cases × ${repeat} · drafter ${drafterName}`);
  out = await runEval(cases, drafter, {
    repeat,
    concurrency,
    onAttempt: (id, a) => console.log(`  ${a.error ? "ERR " : a.grade?.pass ? "pass" : "FAIL"}  ${id.padEnd(20)} ${a.grade ? a.grade.score.toFixed(2) : ""} ${a.ms} ms${a.error ? `  ${a.error}` : ""}${a.grade?.failures.length ? `  ${a.grade.failures.join("; ")}` : ""}`),
  });
  meta = { drafter: drafterName, model: out.results.flatMap((r) => r.attempts).find((a) => a.model)?.model, repeat, date };
}

mkdirSync(outDir, { recursive: true });
const stem = join(outDir, `${meta.drafter.split(" ")[0]}-${date.replace(/[:.]/g, "-")}`);
writeFileSync(`${stem}.json`, JSON.stringify({ meta, summary: out.summary, results: out.results }, null, 2));
const md = report(meta, out.results, out.summary);
writeFileSync(`${stem}.md`, md);

const s = out.summary;
console.log(`\npass ${Math.round(s.passRate * 100)}% of attempts · all repeats pass ${Math.round(s.passAll * 100)}% of cases · mean score ${s.meanScore.toFixed(2)} · ${s.errors} errors`);
if (s.failing.length) console.log(`failing: ${s.failing.join(", ")}`);
console.log(`report: ${stem}.md`);

const minPass = opt("min-pass");
if (minPass && s.passRate < Number(minPass)) process.exitCode = 1;
