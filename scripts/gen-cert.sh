#!/usr/bin/env bash
set -euo pipefail

mkdir -p certs

openssl req -x509 -newkey rsa:2048 \
  -keyout certs/key.pem \
  -out certs/cert.pem \
  -days 365 -nodes \
  -subj "/CN=www.cloudflare.com"

echo "Сертификаты созданы: certs/cert.pem, certs/key.pem"
