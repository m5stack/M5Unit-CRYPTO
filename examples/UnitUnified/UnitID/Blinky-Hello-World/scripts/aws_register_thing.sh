#!/bin/bash
set -e

if [ "$#" -ne 3 ]; then
  echo "Usage: $0 device_cert.crt serial_number region"
  exit 1
fi

DEVICE_CERT=$1
THING_NAME=$2
REGION=$3

POLICY_NAME="M5Unit-ID-Policy"
THING_TYPE="m5unit-id"

echo "[1/6] Validating inputs..."

if ! openssl x509 -in "$DEVICE_CERT" -noout > /dev/null 2>&1; then
  echo "ERROR: $DEVICE_CERT is not a valid X.509 certificate"
  exit 1
fi
echo "Device certificate valid."

if ! aws iot describe-endpoint --endpoint-type iot:Data-ATS --region "$REGION" > /dev/null 2>&1; then
  echo "ERROR: AWS region \"$REGION\" is invalid or inaccessible"
  exit 1
fi
echo "Region \"$REGION\" is valid."

ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text --region "$REGION")

echo "[2/6] Creating or confirming policy \"$POLICY_NAME\"..."
if aws iot get-policy --policy-name "$POLICY_NAME" --region "$REGION" > /dev/null 2>&1; then
  echo "Policy exists."
else
  aws iot create-policy --region "$REGION" \
    --policy-name "$POLICY_NAME" --policy-document "{
  \"Version\": \"2012-10-17\",
  \"Statement\": [
    { \"Effect\": \"Allow\", \"Action\": [\"iot:Connect\"],
      \"Resource\": [\"arn:aws:iot:$REGION:$ACCOUNT_ID:client/\${iot:Connection.Thing.ThingName}\"] },
    { \"Effect\": \"Allow\", \"Action\": [\"iot:Publish\", \"iot:Receive\"],
      \"Resource\": [
        \"arn:aws:iot:$REGION:$ACCOUNT_ID:topic/\${iot:Connection.Thing.ThingName}/*\",
        \"arn:aws:iot:$REGION:$ACCOUNT_ID:topic/\$aws/things/\${iot:Connection.Thing.ThingName}/shadow/*\"] },
    { \"Effect\": \"Allow\", \"Action\": [\"iot:Subscribe\"],
      \"Resource\": [
        \"arn:aws:iot:$REGION:$ACCOUNT_ID:topicfilter/\${iot:Connection.Thing.ThingName}/*\",
        \"arn:aws:iot:$REGION:$ACCOUNT_ID:topicfilter/\$aws/things/\${iot:Connection.Thing.ThingName}/shadow/*\"] },
    { \"Effect\": \"Allow\", \"Action\": [\"iot:UpdateThingShadow\", \"iot:GetThingShadow\"],
      \"Resource\": [
        \"arn:aws:iot:$REGION:$ACCOUNT_ID:topic/\$aws/things/\${iot:Connection.Thing.ThingName}/shadow/*\"] }
  ]}"
  echo "Policy created."
fi

echo "[3/6] Deleting and recreating thing \"$THING_NAME\"..."
if aws iot describe-thing --thing-name "$THING_NAME" --region "$REGION" > /dev/null 2>&1; then
  PRINCIPALS=$(aws iot list-thing-principals --thing-name "$THING_NAME" --region "$REGION" --query "principals[]" --output text)
  for p in $PRINCIPALS; do
    aws iot detach-thing-principal --thing-name "$THING_NAME" --principal "$p" --region "$REGION"
  done
  aws iot delete-thing --thing-name "$THING_NAME" --region "$REGION"
  echo "Thing deleted."
fi

THING_TYPE_ARN=$(aws iot list-thing-types --region "$REGION" \
  --query "thingTypes[?thingTypeName=='$THING_TYPE'].thingTypeArn" --output text)

if [ -z "$THING_TYPE_ARN" ]; then
  echo "Creating thing type \"$THING_TYPE\"..."
  THING_TYPE_ARN=$(aws iot create-thing-type --thing-type-name "$THING_TYPE" --region "$REGION" --query "thingTypeArn" --output text)
fi

aws iot create-thing --thing-name "$THING_NAME" \
  --thing-type-name "$THING_TYPE" \
  --region "$REGION"
echo "Thing \"$THING_NAME\" created."

echo "[4/6] Checking or registering certificate..."

# DER-based SHA1 of device_cert
CERT_SHA1=$(openssl x509 -in "$DEVICE_CERT" -outform DER | shasum -a 1 | cut -d' ' -f1)

echo "Looking for matching certificate in current region..."
CERT_ARN=""
for CERT_ID in $(aws iot list-certificates --region "$REGION" --query "certificates[].certificateId" --output text); do
  TMP_CERT=$(mktemp)
  aws iot describe-certificate --certificate-id "$CERT_ID" --region "$REGION" \
    --query "certificateDescription.certificatePem" --output text > "$TMP_CERT"

  SHA1=$(openssl x509 -in "$TMP_CERT" -outform DER | shasum -a 1| cut -d' ' -f1)
  rm "$TMP_CERT"

  if [ "$SHA1" = "$CERT_SHA1" ]; then
    CERT_ARN=$(aws iot describe-certificate --certificate-id "$CERT_ID" --region "$REGION" \
      --query "certificateDescription.certificateArn" --output text)
    echo "Found matching certificate: $CERT_ARN"
    break
  fi
done

if [ -z "$CERT_ARN" ]; then
  echo "Registering new certificate..."
  CERT_ARN=$(aws iot register-certificate-without-ca \
    --certificate-pem file://"$DEVICE_CERT" \
    --status ACTIVE \
    --region "$REGION" \
    --query certificateArn --output text)
else
  echo "Reusing existing certificate."
fi


echo "[5/6] Attaching certificate to thing..."
aws iot attach-thing-principal --thing-name "$THING_NAME" --principal "$CERT_ARN" --region "$REGION" || echo "Already attached."

echo "[6/6] Attaching policy..."
aws iot attach-policy --policy-name "$POLICY_NAME" --target "$CERT_ARN" --region "$REGION" || echo "Policy already attached."

echo "DONE. Thing \"$THING_NAME\" is ready and bound to certificate."
echo "AWS IoT Endpoint"
aws iot describe-endpoint --endpoint-type iot:Data-ATS --region "$REGION"


