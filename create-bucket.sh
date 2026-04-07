#!/usr/bin/env bash
# =============================================================================
# create-bucket.sh — Create an S3 bucket + IAM user/group/policy for a server
# =============================================================================
# Usage:  ./create-bucket.sh <bucket-prefix> <bucket-name>
# Example: ./create-bucket.sh acme-s3backup server001
#
# This script is designed to be run by an admin user created with
# create-admin-user.sh. The admin's IAM policy is scoped to allow
# only operations on <prefix>-* resources.
#
# What it does:
#   1. Creates the S3 bucket: <prefix>-<name>
#   2. Enables Block Public Access + Versioning on the bucket
#   3. Creates a scoped IAM policy for this bucket only
#   4. Creates an IAM group and attaches the policy
#   5. Creates an IAM user and adds to the group
#   6. Generates access keys for the backup software
#
# Idempotent: Safe to re-run. Existing resources are skipped.
# =============================================================================

set -euo pipefail

# ---------------------------------------------------------------------------
# CONFIGURATION
# ---------------------------------------------------------------------------
AWS_REGION="ap-southeast-2"

# ---------------------------------------------------------------------------
# INPUT VALIDATION
# ---------------------------------------------------------------------------
if [ $# -ne 2 ]; then
  echo "Usage: $0 <bucket-prefix> <bucket-name>"
  echo "Example: $0 acme-s3backup server001"
  exit 1
fi

BUCKET_PREFIX="$1"
BUCKET_SUFFIX="$2"

# Derived names — follow the naming convention consistently
BUCKET_NAME="${BUCKET_PREFIX}-${BUCKET_SUFFIX}"
GROUP_NAME="${BUCKET_PREFIX}-group-${BUCKET_SUFFIX}"
POLICY_NAME="${BUCKET_PREFIX}-policy-${BUCKET_SUFFIX}"
USER_NAME="${BUCKET_PREFIX}-user-${BUCKET_SUFFIX}"

# ---------------------------------------------------------------------------
# HELPERS
# ---------------------------------------------------------------------------
log()  { echo "[INFO]  $(date '+%H:%M:%S') — $*"; }
warn() { echo "[WARN]  $(date '+%H:%M:%S') — $*"; }
error() { echo "[ERROR] $(date '+%H:%M:%S') — $*" >&2; }

group_exists() { aws iam get-group --group-name "$1" &>/dev/null; }
user_exists()  { aws iam get-user  --user-name  "$1" &>/dev/null; }

get_account_id() { aws sts get-caller-identity --query Account --output text; }

# ---------------------------------------------------------------------------
# PRE-FLIGHT
# ---------------------------------------------------------------------------
log "Starting bucket setup for: $BUCKET_SUFFIX"
ACCOUNT_ID=$(get_account_id)
log "AWS Account: $ACCOUNT_ID"
log "Region:      $AWS_REGION"
log ""
log "Will create:"
log "  Bucket:  $BUCKET_NAME"
log "  Group:   $GROUP_NAME"
log "  Policy:  $POLICY_NAME"
log "  User:    $USER_NAME"
echo ""

# ---------------------------------------------------------------------------
# STEP 1: CREATE S3 BUCKET
# ---------------------------------------------------------------------------
# Block Public Access is enabled as defense-in-depth.
# Versioning protects against accidental deletion or overwriting by
# the backup software.
# ---------------------------------------------------------------------------

if aws s3api head-bucket --bucket "$BUCKET_NAME" 2>/dev/null; then
  warn "Bucket already exists: $BUCKET_NAME — skipping."
else
  log "Creating bucket: $BUCKET_NAME"

  # ap-southeast-2 requires LocationConstraint (only us-east-1 omits it)
  aws s3api create-bucket \
    --bucket "$BUCKET_NAME" \
    --region "$AWS_REGION" \
    --create-bucket-configuration LocationConstraint="$AWS_REGION"

  # Block all public access
  aws s3api put-public-access-block \
    --bucket "$BUCKET_NAME" \
    --public-access-block-configuration \
      "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"

  # Enable versioning for backup safety
  aws s3api put-bucket-versioning \
    --bucket "$BUCKET_NAME" \
    --versioning-configuration Status=Enabled

  log "Bucket created and secured: $BUCKET_NAME"
fi

echo ""

# ---------------------------------------------------------------------------
# STEP 2: CREATE SCOPED IAM POLICY
# ---------------------------------------------------------------------------
# This policy grants the minimum permissions a backup agent needs:
#
# ListAllMyBuckets:
#   Needed for some backup tools to enumerate buckets. Only exposes
#   bucket names, not contents. Cannot be scoped to specific buckets
#   (AWS API limitation).
#
# ListBucket:
#   List objects in this bucket only. Needed for incremental backups
#   to compare local vs remote file lists.
#
# GetObject:
#   Download objects from this bucket only. Needed for restore operations.
#
# PutObject:
#   Upload objects to this bucket only. Core backup operation.
#
# DeleteObject:
#   Included here because backup software often needs to manage retention
#   (delete old backups). Combined with versioning, deleted objects are
#   recoverable. Remove this action if you want admins-only deletion.
#
# GetBucketLocation + GetBucketVersioning:
#   Some backup tools query these for configuration. Read-only, harmless.
#
# ListMultipartUploadParts + AbortMultipartUpload + ListBucketMultipartUploads:
#   Required for reliable large-file uploads. Without these, interrupted
#   uploads of large backup files leave orphaned parts that cost money.
#
# Explicit Deny:
#   Blocks all S3 actions on any bucket other than this one.
#   Safety net — prevents cross-bucket access even if a broader policy
#   is accidentally attached.
# ---------------------------------------------------------------------------

POLICY_ARN="arn:aws:iam::${ACCOUNT_ID}:policy/${POLICY_NAME}"

POLICY_DOC=$(cat <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ListBuckets",
      "Effect": "Allow",
      "Action": "s3:ListAllMyBuckets",
      "Resource": "arn:aws:s3:::*"
    },
    {
      "Sid": "BucketLevelAccess",
      "Effect": "Allow",
      "Action": [
        "s3:ListBucket",
        "s3:GetBucketLocation",
        "s3:GetBucketVersioning",
        "s3:ListBucketMultipartUploads"
      ],
      "Resource": "arn:aws:s3:::${BUCKET_NAME}"
    },
    {
      "Sid": "ObjectLevelAccess",
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:PutObject",
        "s3:DeleteObject",
        "s3:ListMultipartUploadParts",
        "s3:AbortMultipartUpload"
      ],
      "Resource": "arn:aws:s3:::${BUCKET_NAME}/*"
    },
    {
      "Sid": "DenyOtherBuckets",
      "Effect": "Deny",
      "NotAction": "s3:ListAllMyBuckets",
      "NotResource": [
        "arn:aws:s3:::${BUCKET_NAME}",
        "arn:aws:s3:::${BUCKET_NAME}/*"
      ]
    }
  ]
}
EOF
)

if aws iam get-policy --policy-arn "$POLICY_ARN" &>/dev/null; then
  warn "Policy already exists: $POLICY_NAME"
else
  aws iam create-policy \
    --policy-name "$POLICY_NAME" \
    --policy-document "$POLICY_DOC" \
    --description "Scoped S3 backup access for ${BUCKET_SUFFIX}"
  log "Created policy: $POLICY_NAME"
fi

echo ""

# ---------------------------------------------------------------------------
# STEP 3: CREATE IAM GROUP
# ---------------------------------------------------------------------------

if group_exists "$GROUP_NAME"; then
  warn "Group already exists: $GROUP_NAME"
else
  aws iam create-group --group-name "$GROUP_NAME"
  log "Created group: $GROUP_NAME"
fi

# Attach policy to group (idempotent)
aws iam attach-group-policy \
  --group-name "$GROUP_NAME" \
  --policy-arn "$POLICY_ARN"
log "Policy attached to group: $GROUP_NAME"

echo ""

# ---------------------------------------------------------------------------
# STEP 4: CREATE IAM USER + ACCESS KEYS
# ---------------------------------------------------------------------------

if user_exists "$USER_NAME"; then
  warn "User already exists: $USER_NAME"
else
  aws iam create-user --user-name "$USER_NAME"
  log "Created user: $USER_NAME"
fi

# Add user to group (idempotent)
aws iam add-user-to-group \
  --group-name "$GROUP_NAME" \
  --user-name "$USER_NAME"
log "Added $USER_NAME to group $GROUP_NAME"

# Generate access keys
EXISTING_KEYS=$(aws iam list-access-keys --user-name "$USER_NAME" --query 'AccessKeyMetadata | length(@)' --output text)

if [ "$EXISTING_KEYS" -ge 2 ]; then
  warn "User $USER_NAME already has 2 access keys (AWS maximum). Skipping key creation."
  warn "Delete an existing key if you need a new one:"
  warn "  aws iam delete-access-key --user-name $USER_NAME --access-key-id <key-id>"
elif [ "$EXISTING_KEYS" -ge 1 ]; then
  warn "User $USER_NAME already has an access key. Skipping to avoid duplicates."
  warn "If you need a new key, delete the existing one first:"
  aws iam list-access-keys --user-name "$USER_NAME" --output table
else
  log "Generating access keys..."
  ACCESS_KEY_OUTPUT=$(aws iam create-access-key --user-name "$USER_NAME" --output json)

  ACCESS_KEY_ID=$(echo "$ACCESS_KEY_OUTPUT" | python3 -c "import sys,json; print(json.load(sys.stdin)['AccessKey']['AccessKeyId'])")
  SECRET_KEY=$(echo "$ACCESS_KEY_OUTPUT" | python3 -c "import sys,json; print(json.load(sys.stdin)['AccessKey']['SecretAccessKey'])")

  echo ""
  echo "=============================================="
  echo "  ACCESS KEYS FOR BACKUP SOFTWARE"
  echo "  (The secret key cannot be retrieved again)"
  echo "=============================================="
  echo ""
  echo "  Bucket:           $BUCKET_NAME"
  echo "  Region:           $AWS_REGION"
  echo "  User:             $USER_NAME"
  echo "  Access Key ID:    $ACCESS_KEY_ID"
  echo "  Secret Access Key: $SECRET_KEY"
  echo ""
  echo "  Backup software config:"
  echo "    S3 Endpoint:    s3.${AWS_REGION}.amazonaws.com"
  echo "    Bucket:         $BUCKET_NAME"
  echo "    Access Key:     $ACCESS_KEY_ID"
  echo "    Secret Key:     $SECRET_KEY"
  echo "    Region:         $AWS_REGION"
  echo ""
  echo "=============================================="
fi

echo ""

# ---------------------------------------------------------------------------
# SUMMARY
# ---------------------------------------------------------------------------
echo "----------------------------------------------"
echo "  SETUP COMPLETE: $BUCKET_SUFFIX"
echo "----------------------------------------------"
echo "  Bucket:  $BUCKET_NAME"
echo "  Group:   $GROUP_NAME"
echo "  Policy:  $POLICY_NAME"
echo "  User:    $USER_NAME"
echo "  Region:  $AWS_REGION"
echo "----------------------------------------------"
echo ""
log "Done. Configure your backup software with the access keys above."
