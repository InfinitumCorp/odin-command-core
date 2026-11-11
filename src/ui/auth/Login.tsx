import { useEffect, useState, type FormEvent } from "react";
import { enroll, enrollSecurityKey, fetchPolicy, resume, securityKeysSupported, signIn, signOut, type Me, type Signer } from "./client";
import { enrolledIds } from "./keystore";

export interface Session {
  me: Me;
  signer: Signer;
}

/** Shows the console only to a signed-in operator whose key is on this device. */
export function AuthGate({ children }: { children: (s: Session, signOut: () => void) => React.ReactNode }) {
  const [session, setSession] = useState<Session | null>();

  useEffect(() => {
    resume().then((s) => setSession(s ?? null), () => setSession(null));
  }, []);

  if (session === undefined) return <div className="login-shell"><p className="dim">Checking session…</p></div>;
  if (session === null) return <Login onSignedIn={setSession} />;
  return <>{children(session, () => void signOut().then(() => setSession(null)))}</>;
}

const POLICY_TEXT = {
  off: "",
  commander: "Policy: commanders must use a FIDO2 security key.",
  all: "Policy: every operator must use a FIDO2 security key.",
} as const;

function Login({ onSignedIn }: { onSignedIn: (s: Session) => void }) {
  const hwSupported = securityKeysSupported();
  const [mode, setMode] = useState<"signin" | "enroll">("signin");
  const [keyType, setKeyType] = useState<"webauthn" | "software">(hwSupported ? "webauthn" : "software");
  const [operatorId, setOperatorId] = useState("");
  const [code, setCode] = useState("");
  const [busy, setBusy] = useState(false);
  const [touch, setTouch] = useState(false);
  const [error, setError] = useState<string>();
  const [known, setKnown] = useState<string[]>([]);
  const [policy, setPolicy] = useState<"off" | "commander" | "all">("off");

  useEffect(() => {
    enrolledIds().then((ids) => {
      setKnown(ids);
      if (ids.length === 0) setMode("enroll");
      else setOperatorId((v) => v || ids[0]);
    }, () => undefined);
    fetchPolicy().then((p) => setPolicy(p.requireHardware), () => undefined);
  }, []);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    const id = operatorId.trim().toUpperCase();
    setBusy(true);
    setError(undefined);
    try {
      if (mode === "enroll") {
        if (keyType === "webauthn") {
          setTouch(true);
          await enrollSecurityKey(id, code);
        } else await enroll(id, code);
        setCode("");
      }
      setTouch(true);
      onSignedIn(await signIn(id));
    } catch (err) {
      setError(err instanceof Error ? err.message : "failed");
    } finally {
      setBusy(false);
      setTouch(false);
    }
  };

  return (
    <div className="login-shell">
      <div className="classification">UNCLASSIFIED // EXERCISE // SIMULATED DATA ONLY</div>
      <form className="login" onSubmit={submit}>
        <div className="brand">ODIN<span className="deg">°</span><small>Command Core</small></div>
        <div className="seg" role="tablist">
          <button type="button" role="tab" aria-selected={mode === "signin"} className={mode === "signin" ? "on" : ""} onClick={() => setMode("signin")}>Sign in</button>
          <button type="button" role="tab" aria-selected={mode === "enroll"} className={mode === "enroll" ? "on" : ""} onClick={() => setMode("enroll")}>Enroll</button>
        </div>
        <label>
          Operator ID
          <input name="operatorId" autoComplete="username" value={operatorId} onChange={(e) => setOperatorId(e.target.value)} required list="known-ops" spellCheck={false} />
          <datalist id="known-ops">{known.map((k) => <option key={k} value={k} />)}</datalist>
        </label>
        {mode === "enroll" && (
          <>
            <fieldset className="keytype">
              <legend>Signing key</legend>
              <label className="radio">
                <input type="radio" name="keyType" value="webauthn" checked={keyType === "webauthn"} disabled={!hwSupported} onChange={() => setKeyType("webauthn")} />
                Security key (FIDO2)
              </label>
              <label className="radio">
                <input type="radio" name="keyType" value="software" checked={keyType === "software"} onChange={() => setKeyType("software")} />
                This browser
              </label>
            </fieldset>
            <label>
              Enrollment code
              <input name="code" type="password" autoComplete="one-time-code" value={code} onChange={(e) => setCode(e.target.value)} required spellCheck={false} />
            </label>
          </>
        )}
        <button className="approve" disabled={busy}>{busy ? (touch ? "Touch your security key if it blinks…" : "Working…") : mode === "enroll" ? "Enroll and sign in" : "Sign in"}</button>
        {error && <p className="login-error" role="alert">{error}</p>}
        {policy !== "off" && <p className="small-print policy">{POLICY_TEXT[policy]}</p>}
        <p className="dim small-print">
          {mode === "enroll"
            ? keyType === "webauthn"
              ? "Registers a FIDO2 security key (touch and PIN) to your operator ID with the one-time code from your administrator. Every command you approve is signed on the key itself."
              : "Creates a signing key in this browser that cannot be exported, and binds it to your operator ID with the one-time code from your administrator."
            : known.length
              ? `Keys on this device: ${known.join(", ")}. Signing in proves you hold the key; no password is sent.`
              : "This device has no operator keys yet. Enroll it first."}
        </p>
      </form>
    </div>
  );
}
