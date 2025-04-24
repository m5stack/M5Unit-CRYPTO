#!/bin/bash
set -e

DIR="./data"
DER_FILE="AmazonRootCA1.der"
PEM_URL="https://www.amazontrust.com/repository/AmazonRootCA1.pem"

mkdir -p "$DIR"

echo "[1/3] Downloading PEM from $PEM_URL..."
curl -sSL "$PEM_URL" -o "$DIR/temp.pem"

echo "[2/3] Converting to DER format..."
openssl x509 -outform der -in "$DIR/temp.pem" -out "$DIR/$DER_FILE"

rm "$DIR/temp.pem"

echo "[3/3] Done! Saved as $DIR/$DER_FILE"
