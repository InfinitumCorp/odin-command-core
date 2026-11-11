// Vitest global setup: the test-only PKI (src/server/__fixtures__/pki) is not committed, since
// it holds private keys. Generate it on first run with openssl (scripts/gen-test-pki.sh).
import { execFileSync } from "node:child_process";
import { existsSync } from "node:fs";

export default function setup() {
  if (existsSync("src/server/__fixtures__/pki/server.key")) return;
  console.log("[test] generating the test-only PKI (scripts/gen-test-pki.sh)");
  execFileSync("bash", ["scripts/gen-test-pki.sh"], { stdio: "inherit" });
}
