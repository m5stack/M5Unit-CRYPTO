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
  ]}" > /dev/null
  echo "Policy created."
fi

echo "[3/6] Creating or confirming thing \"$THING_NAME\"..."
THING_TYPE_DEPRECATED=$(aws iot list-thing-types --region "$REGION" --thing-type-name "$THING_TYPE" \
  --query "thingTypes[0].thingTypeMetadata.deprecated" --output text)
if [ "$THING_TYPE_DEPRECATED" = "None" ] || [ -z "$THING_TYPE_DEPRECATED" ]; then
  echo "Creating thing type \"$THING_TYPE\"..."
  aws iot create-thing-type --thing-type-name "$THING_TYPE" --region "$REGION" > /dev/null
elif [ "$THING_TYPE_DEPRECATED" = "True" ]; then
  echo "ERROR: thing type \"$THING_TYPE\" is deprecated. Undeprecate it (aws iot deprecate-thing-type --undo-deprecate) or delete it"
  exit 1
fi

if aws iot describe-thing --thing-name "$THING_NAME" --region "$REGION" > /dev/null 2>&1; then
  echo "Thing exists."
else
  aws iot create-thing --thing-name "$THING_NAME" --thing-type-name "$THING_TYPE" --region "$REGION" > /dev/null
  echo "Thing \"$THING_NAME\" created."
fi

echo "[4/6] Checking or registering certificate..."

# The AWS IoT certificate ID is the SHA-256 of the DER encoded certificate
CERT_ID=$(openssl x509 -in "$DEVICE_CERT" -outform DER | shasum -a 256 | cut -d' ' -f1)

CERT_STATUS=$(aws iot describe-certificate --certificate-id "$CERT_ID" --region "$REGION" \
  --query "certificateDescription.status" --output text 2> /dev/null || true)
if [ -z "$CERT_STATUS" ]; then
  echo "Registering new certificate..."
  CERT_ARN=$(aws iot register-certificate-without-ca \
    --certificate-pem file://"$DEVICE_CERT" \
    --status ACTIVE \
    --region "$REGION" \
    --query certificateArn --output text)
else
  echo "Found the certificate (status: $CERT_STATUS)."
  case "$CERT_STATUS" in
    ACTIVE) ;;
    INACTIVE)
      echo "Activating the certificate..."
      aws iot update-certificate --certificate-id "$CERT_ID" --new-status ACTIVE --region "$REGION"
      ;;
    *)
      echo "ERROR: the certificate is $CERT_STATUS and cannot be used"
      exit 1
      ;;
  esac
  CERT_ARN=$(aws iot describe-certificate --certificate-id "$CERT_ID" --region "$REGION" \
    --query "certificateDescription.certificateArn" --output text)
fi
echo "Certificate: $CERT_ARN"

echo "[5/6] Attaching certificate to thing..."
aws iot attach-thing-principal --thing-name "$THING_NAME" --principal "$CERT_ARN" --region "$REGION"

echo "[6/6] Attaching policy..."
aws iot attach-policy --policy-name "$POLICY_NAME" --target "$CERT_ARN" --region "$REGION"

echo "DONE. Thing \"$THING_NAME\" is ready and bound to certificate."
echo "AWS IoT Endpoint"
aws iot describe-endpoint --endpoint-type iot:Data-ATS --region "$REGION"


