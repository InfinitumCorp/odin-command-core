// SCALVS.ai drafter: asks Claude for courses of action for one decision point.
// Runs server-side only (the API key never reaches the browser). The model's output
// is schema-constrained here and then re-validated by the core before a commander sees it.

import Anthropic from "@anthropic-ai/sdk";
import { z } from "zod";
import type { Situation } from "../core/decide";
import type { CoaProposal } from "../core/types";

export const MODEL = "claude-opus-5-5";

const VERBS = ["observe", "relay", "resupply", "evacuate"] as const;

const ProposalSchema = z.object({
  coas: z.array(
    z.object({
      title: z.string().min(1),
      rationale: z.string().min(1),
      risk: z.enum(["low", "medium", "high"]),
      actions: z.array(
        z.object({
          assetId: z.string(),
          verb: z.enum(VERBS),
          target: z.object({ x: z.number(), y: z.number() }),
          note: z.string(),
        }),
      ),
    }),
  ),
});

/** JSON Schema handed to the API so the response is always well-formed. */
const OUTPUT_SCHEMA = {
  type: "object",
  additionalProperties: false,
  required: ["coas"],
  properties: {
    coas: {
      type: "array",
      items: {
        type: "object",
        additionalProperties: false,
        required: ["title", "rationale", "risk", "actions"],
        properties: {
          title: { type: "string" },
          rationale: { type: "string" },
          risk: { type: "string", enum: ["low", "medium", "high"] },
          actions: {
            type: "array",
            items: {
              type: "object",
              additionalProperties: false,
              required: ["assetId", "verb", "target", "note"],
              properties: {
                assetId: { type: "string" },
                verb: { type: "string", enum: [...VERBS] },
                target: {
                  type: "object",
                  additionalProperties: false,
                  required: ["x", "y"],
                  properties: { x: { type: "number" }, y: { type: "number" } },
                },
                note: { type: "string" },
              },
            },
          },
        },
      },
    },
  },
} as const;

export const SYSTEM_PROMPT = `You are SCALVS.ai, the course-of-action drafting component of ODIN°, a human-commanded decision-support system used in a training exercise with simulated data.

A decision point has been raised. Draft up to three distinct courses of action (COAs) for the commander, best first. A commander reviews every COA and nothing happens unless they approve it, so your job is to give them clear, honest options, not to decide.

The situation arrives as JSON. Positions are kilometres on a 100 x 100 grid. etaMin is each asset's travel time to the decision point (null for fixed sensors).

Rules:
- Only task assets whose "available" is true, and only with a verb listed in that asset's "allowedVerbs". Use each asset at most once per COA. Refer to assets by "id".
- Targets must lie inside the grid. For observe and resupply/evacuate, target the decision point (or the track position if one is given). For relay, a point between the team and friendly assets is often better than the point itself.
- The only task types are observe, relay, resupply and evacuate. Do not propose anything else.
- An option with no actions (hold, monitor with existing sensors, or escalate) is valid; include one when holding is a reasonable choice.
- Make the options genuinely different (different assets, speed versus exposure, or cost), not small variations.
- Rationale: one or two sentences on why this option and what it trades off, citing ETA or battery where it matters. Title: short and imperative, naming the main asset by callsign.
- Risk is the risk to the mission and to your own assets: low, medium or high.
- If no available asset fits, return a single no-action COA that recommends escalation and says what is missing.`;

export class DraftUnavailable extends Error {}

export interface DraftResult {
  proposals: CoaProposal[];
  model: string;
}

export async function draftWithClaude(situation: Situation, client: Anthropic = new Anthropic()): Promise<DraftResult> {
  const response = await client.beta.messages.create({
    model: MODEL,
    max_tokens: 16000,
    betas: ["server-side-fallback-2026-07-01"],
    fallbacks: "default",
    output_config: { effort: "medium", format: { type: "json_schema", schema: OUTPUT_SCHEMA } },
    system: SYSTEM_PROMPT,
    messages: [{ role: "user", content: `Situation:\n${JSON.stringify(situation, null, 2)}` }],
  });

  if (response.stop_reason === "refusal") {
    throw new DraftUnavailable(`model declined (${response.stop_details?.category ?? "no category"})`);
  }
  if (response.stop_reason === "max_tokens") throw new DraftUnavailable("response truncated");

  const text = response.content.flatMap((b) => (b.type === "text" ? [b.text] : [])).join("");
  let json: unknown;
  try {
    json = JSON.parse(text);
  } catch {
    throw new DraftUnavailable("response was not JSON");
  }
  const parsed = ProposalSchema.safeParse(json);
  if (!parsed.success) throw new DraftUnavailable(`response did not match schema: ${parsed.error.issues[0]?.message}`);
  return { proposals: parsed.data.coas, model: response.model ?? MODEL };
}

/** Maps SDK failures to a short operator-facing reason; the console then keeps the rule-based options. */
export function describeFailure(e: unknown): string {
  if (e instanceof DraftUnavailable) return e.message;
  if (e instanceof Anthropic.AuthenticationError) return "no valid Anthropic credentials on the server";
  if (e instanceof Anthropic.RateLimitError) return "rate limited";
  if (e instanceof Anthropic.APIConnectionError) return "cannot reach the Anthropic API";
  if (e instanceof Anthropic.APIError) return `Anthropic API error ${e.status}`;
  if (e instanceof Error && /api key|apiKey|authToken|credentials/i.test(e.message)) return "no Anthropic credentials configured on the server";
  return "drafter error";
}
