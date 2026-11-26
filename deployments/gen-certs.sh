#!/usr/bin/env bash
set -euo pipefail

# Prevent Git Bash on Windows from rewriting -subj /CN=... arguments.
export MSYS_NO_PATHCONV=1

CERT_DIR="${URGUARD_RUNTIME_CERT_DIR:-/certs}"
DAYS="${URGUARD_CERT_DAYS:-7}"
FORCE_REGEN="${FORCE_REGEN:-false}"

mkdir -p "$CERT_DIR"

if [ "$FORCE_REGEN" != "true" ] && [ -f "$CERT_DIR/ca.crt" ] && [ -f "$CERT_DIR/controlplane.crt" ] && [ -f "$CERT_DIR/node-a.crt" ] && [ -f "$CERT_DIR/node-b.crt" ] && [ -f "$CERT_DIR/node-c.crt" ]; then
  echo "Runtime mTLS certificates already present in $CERT_DIR"
  exit 0
fi

echo "Generating ephemeral internal mTLS CA and service certificates in $CERT_DIR..."

openssl genrsa -out "$CERT_DIR/ca.key" 4096
openssl req -x509 -new -nodes \
  -key "$CERT_DIR/ca.key" \
  -sha256 \
  -days "$DAYS" \
  -subj "/O=urGuard/CN=urguard-internal-ca" \
  -out "$CERT_DIR/ca.crt"

generate_leaf() {
  local name="$1"
  local san="$2"
  local ext_file="$CERT_DIR/${name}.ext"

  openssl genrsa -out "$CERT_DIR/${name}.key" 2048
  openssl req -new \
    -key "$CERT_DIR/${name}.key" \
    -subj "/O=urGuard/CN=${name}" \
    -out "$CERT_DIR/${name}.csr"

  cat > "$ext_file" <<EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth, clientAuth
subjectAltName = ${san}
EOF

  openssl x509 -req \
    -in "$CERT_DIR/${name}.csr" \
    -CA "$CERT_DIR/ca.crt" \
    -CAkey "$CERT_DIR/ca.key" \
    -CAcreateserial \
    -out "$CERT_DIR/${name}.crt" \
    -days "$DAYS" \
    -sha256 \
    -extfile "$ext_file"

  rm -f "$CERT_DIR/${name}.csr" "$ext_file"
}

generate_leaf "controlplane" "DNS:controlplane,DNS:localhost,IP:127.0.0.1"
generate_leaf "node-a" "DNS:node-a,DNS:localhost,IP:127.0.0.1"
generate_leaf "node-b" "DNS:node-b,DNS:localhost,IP:127.0.0.1"
generate_leaf "node-c" "DNS:node-c,DNS:localhost,IP:127.0.0.1"

chmod 0644 "$CERT_DIR"/*.crt
chmod 0640 "$CERT_DIR"/*.key

if [ "$(id -u)" -eq 0 ]; then
  chown -R 65532:65532 "$CERT_DIR"
fi

echo "Generated mTLS CA and leaf certificates for controlplane, node-a, node-b, node-c."
