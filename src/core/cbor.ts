// Minimal CBOR (RFC 8949) for WebAuthn: attestation objects and COSE keys. Supports the
// subset those use (unsigned/negative ints, byte and text strings, arrays, maps, simple
// true/false/null). Indefinite lengths, floats and tags are refused. The decoder is strict
// about bounds so a malformed attestation cannot read past its buffer.

export type Cbor = number | Uint8Array | string | Cbor[] | Map<Cbor, Cbor> | boolean | null;

export class CborError extends Error {}

const MAX_DEPTH = 16;

export function decodeCbor(bytes: Uint8Array): { value: Cbor; length: number } {
  let pos = 0;
  const need = (n: number) => {
    if (pos + n > bytes.length) throw new CborError("truncated CBOR");
  };
  const arg = (info: number): number => {
    if (info < 24) return info;
    const n = info === 24 ? 1 : info === 25 ? 2 : info === 26 ? 4 : info === 27 ? 8 : 0;
    if (!n) throw new CborError("unsupported CBOR length encoding");
    need(n);
    let v = 0;
    for (let i = 0; i < n; i++) v = v * 256 + bytes[pos++];
    if (!Number.isSafeInteger(v)) throw new CborError("CBOR integer too large");
    return v;
  };
  const item = (depth: number): Cbor => {
    if (depth > MAX_DEPTH) throw new CborError("CBOR nested too deeply");
    need(1);
    const b = bytes[pos++];
    const major = b >> 5;
    const info = b & 31;
    switch (major) {
      case 0:
        return arg(info);
      case 1:
        return -1 - arg(info);
      case 2: {
        const n = arg(info);
        need(n);
        const out = bytes.slice(pos, pos + n);
        pos += n;
        return out;
      }
      case 3: {
        const n = arg(info);
        need(n);
        const s = new TextDecoder("utf-8", { fatal: true }).decode(bytes.subarray(pos, pos + n));
        pos += n;
        return s;
      }
      case 4: {
        const n = arg(info);
        const out: Cbor[] = [];
        for (let i = 0; i < n; i++) out.push(item(depth + 1));
        return out;
      }
      case 5: {
        const n = arg(info);
        const out = new Map<Cbor, Cbor>();
        for (let i = 0; i < n; i++) {
          const k = item(depth + 1);
          out.set(k, item(depth + 1));
        }
        return out;
      }
      case 7:
        if (info === 20) return false;
        if (info === 21) return true;
        if (info === 22) return null;
        throw new CborError("unsupported CBOR simple value");
      default:
        throw new CborError("unsupported CBOR type (tag)");
    }
  };
  const value = item(0);
  return { value, length: pos };
}

/** Encoder for the same subset (tests and the emulated authenticator). */
export function encodeCbor(v: Cbor): Uint8Array {
  const out: number[] = [];
  const head = (major: number, n: number) => {
    if (n < 24) out.push((major << 5) | n);
    else if (n < 256) out.push((major << 5) | 24, n);
    else if (n < 65536) out.push((major << 5) | 25, n >> 8, n & 255);
    else out.push((major << 5) | 26, (n >>> 24) & 255, (n >> 16) & 255, (n >> 8) & 255, n & 255);
  };
  const enc = (x: Cbor) => {
    if (typeof x === "number") return x >= 0 ? head(0, x) : head(1, -1 - x);
    if (typeof x === "string") {
      const b = new TextEncoder().encode(x);
      head(3, b.length);
      return void out.push(...b);
    }
    if (x instanceof Uint8Array) {
      head(2, x.length);
      return void out.push(...x);
    }
    if (Array.isArray(x)) {
      head(4, x.length);
      return x.forEach(enc);
    }
    if (x instanceof Map) {
      head(5, x.size);
      for (const [k, val] of x) {
        enc(k);
        enc(val);
      }
      return;
    }
    out.push(x === false ? 0xf4 : x === true ? 0xf5 : 0xf6);
  };
  enc(v);
  return new Uint8Array(out);
}
