#!/usr/bin/env bash
# Regenerates the TEST-ONLY PKI used by src/server/webauthn.test.ts and mtls.test.ts.
# Generated locally (the tests run this on first use); never committed, never trusted anywhere else.
set -euo pipefail
out="${1:-src/server/__fixtures__/pki}"
mkdir -p "$out"
cd "$out"
export MSYS_NO_PATHCONV=1
ec() { openssl ecparam -name prime256v1 -genkey -noout -out "$1.key" && openssl pkcs8 -topk8 -nocrypt -in "$1.key" -out "$1.key.p8" && mv "$1.key.p8" "$1.key"; }
root() { ec "$1"; openssl req -x509 -new -key "$1.key" -sha256 -days 3650 -subj "$2" -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" -out "$1.pem"; }
leaf() { # name subject issuer extfile-lines...
  local n="$1" s="$2" i="$3"; shift 3
  ec "$n"
  openssl req -new -key "$n.key" -subj "$s" -out "$n.csr"
  printf '%s\n' "basicConstraints=critical,CA:FALSE" "$@" > "$n.ext"
  openssl x509 -req -in "$n.csr" -CA "$i.pem" -CAkey "$i.key" -CAcreateserial -days 3650 -sha256 -extfile "$n.ext" -out "$n.pem"
  rm -f "$n.csr" "$n.ext"
}
# FIDO attestation: an approved maker's root and one of its model certificates; an unknown maker.
root att-root "/C=US/O=ODIN Test Key Maker/CN=ODIN Test Attestation Root"
leaf att-leaf "/C=US/O=ODIN Test Key Maker/OU=Authenticator Attestation/CN=ODIN Test Key Model 1" att-root
root rogue-root "/C=US/O=Unknown Maker/CN=Unknown Attestation Root"
leaf rogue-leaf "/C=US/O=Unknown Maker/OU=Authenticator Attestation/CN=Unknown Key" rogue-root
# CAC/PIV over mutual TLS: an issuing CA, the server, two operators' client certificates.
root piv-ca "/C=US/O=ODIN Test/CN=ODIN Test PIV CA"
leaf server "/CN=localhost" piv-ca "subjectAltName=DNS:localhost,IP:127.0.0.1" "extendedKeyUsage=serverAuth"
leaf cdr1 "/C=US/O=ODIN Test/CN=CDR-1 Test Commander" piv-ca "extendedKeyUsage=clientAuth"
leaf other "/C=US/O=ODIN Test/CN=Someone Else" piv-ca "extendedKeyUsage=clientAuth"
rm -f *.srl
echo "test PKI written to $out"
