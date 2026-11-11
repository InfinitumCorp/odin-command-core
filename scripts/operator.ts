#!/usr/bin/env node
// ODIN° operator administration. Run on the server host with plain Node (22.18+ / 23.6+):
//
//   node scripts/operator.ts add CDR-1 --role commander --name "Maj. Example"
//   node scripts/operator.ts list
//   node scripts/operator.ts reset CDR-1          revoke keys, issue a new enrollment code
//   node scripts/operator.ts role ANL-4 commander
//   node scripts/operator.ts disable ANL-4 | enable ANL-4
//   node scripts/operator.ts bind-cert CDR-1 cac.pem   require this CAC/PIV certificate (mTLS)
//   node scripts/operator.ts unbind-cert CDR-1
//
// `add` and `reset` print a one-time enrollment code. Hand it to the operator over a
// separate channel; it is stored only as a hash and expires after 24 hours.
// Options: --store <path> (default .odin/operators.json, or $ODIN_OPERATOR_STORE)

import { X509Certificate } from "node:crypto";
import { readFileSync } from "node:fs";
import { DEFAULT_STORE_PATH, ENROLLMENT_TTL_HOURS, OperatorStore, StoreError, type Role } from "../src/server/operatorStore.ts";

const args = process.argv.slice(2);
const opt = (name: string) => {
  const i = args.indexOf(`--${name}`);
  if (i < 0) return undefined;
  const v = args[i + 1];
  args.splice(i, 2);
  return v;
};
const store = new OperatorStore(opt("store") ?? process.env.ODIN_OPERATOR_STORE ?? DEFAULT_STORE_PATH);
const role = opt("role") as Role | undefined;
const name = opt("name");
const [cmd, id, extra] = args;
const oneLine = (dn: string) => dn.split(/\r?\n/).join(", ");

function showCode(opId: string, code: string) {
  console.log(`Enrollment code for ${opId} (valid ${ENROLLMENT_TTL_HOURS} h, single use):\n\n    ${code}\n`);
  console.log("Give it to the operator over a separate channel. It is not stored and cannot be shown again.");
}

try {
  switch (cmd) {
    case "add":
      if (!id || !role) throw new StoreError("usage: add <ID> --role commander|analyst [--name NAME]");
      showCode(id, store.add(id, role, name ?? id));
      break;
    case "reset":
      if (!id) throw new StoreError("usage: reset <ID>");
      showCode(id, store.reset(id));
      console.log("All previous keys for this operator are revoked.");
      break;
    case "role":
      if (!id || !extra) throw new StoreError("usage: role <ID> commander|analyst");
      store.setRole(id, extra as Role);
      console.log(`${id} is now ${extra}.`);
      break;
    case "disable":
    case "enable":
      if (!id) throw new StoreError(`usage: ${cmd} <ID>`);
      store.setDisabled(id, cmd === "disable");
      console.log(`${id} ${cmd}d.`);
      break;
    case "bind-cert": {
      if (!id || !extra) throw new StoreError("usage: bind-cert <ID> <certificate.pem>");
      const cert = new X509Certificate(readFileSync(extra));
      if (cert.ca) throw new StoreError("that is a CA certificate; bind the operator's own certificate");
      store.bindCert(id, { fingerprint256: cert.fingerprint256, subject: oneLine(cert.subject) });
      console.log(`${id} must now connect with the certificate ${oneLine(cert.subject)}`);
      console.log(`  SHA-256 ${cert.fingerprint256}, valid until ${cert.validTo}`);
      console.log("The server needs ODIN_TLS_CERT/ODIN_TLS_KEY and ODIN_TLS_CLIENT_CA (the issuing CA) for this to be checked.");
      break;
    }
    case "unbind-cert":
      if (!id) throw new StoreError("usage: unbind-cert <ID>");
      store.unbindCert(id);
      console.log(`${id} no longer needs a client certificate.`);
      break;
    case "list":
      for (const o of store.list()) {
        const keys = o.keys.filter((k) => !k.revokedAt);
        const hw = keys.filter((k) => k.kind === "webauthn").length;
        const kinds = keys.length ? `${keys.length} active key(s)${hw ? `, ${hw} security key(s)` : ""}` : "no active keys";
        const state = o.disabled ? "DISABLED" : o.enrollment ? `awaiting enrollment until ${o.enrollment.expiresAt}` : kinds;
        console.log(`${o.id.padEnd(12)} ${o.role.padEnd(10)} ${o.name.padEnd(24)} ${state}${o.clientCert ? `  [cert ${o.clientCert.fingerprint256.slice(0, 17)}…]` : ""}`);
      }
      break;
    default:
      console.log("commands: add, list, reset, role, disable, enable, bind-cert, unbind-cert (see header of scripts/operator.ts)");
      process.exitCode = cmd ? 2 : 0;
  }
} catch (e) {
  console.error(e instanceof StoreError ? `error: ${e.message}` : e);
  process.exitCode = 1;
}
