#!/bin/sh
set -eu

CERT_DIR=/etc/nginx/tls
KEY_FILE="$CERT_DIR/tls.key"
CERT_FILE="$CERT_DIR/tls.crt"

mkdir -p "$CERT_DIR"
if [ ! -s "$KEY_FILE" ] || [ ! -s "$CERT_FILE" ]; then
    openssl req -x509 -nodes -newkey rsa:3072 -sha256 -days 825 \
        -keyout "$KEY_FILE" -out "$CERT_FILE" \
        -subj "/CN=otalon-ot-lab" \
        -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
    chmod 0600 "$KEY_FILE"
fi
