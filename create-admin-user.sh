#!/usr/bin/env bash
# =============================================================================
# create-admin-user.sh — Create or add an admin user for S3 backup management
# =============================================================================
# Usage:  ./create-admin-user.sh <bucket-prefix> <admin-username>
# Example: ./create-admin-user.sh acme-s3backup admin.john
#
# What it does:
#   1. Creates the admin policy (if it doesn't exist) — grants:
#      - Full S3 access to all <prefix>-* buckets
#      - Scoped IAM permissions to manage only <prefix>-* entities
#   2. Creates the admin group (if it doesn't exist)
#   3. Attaches the policy to the group
#   4. Creates the IAM user (if it doesn't exist)
#   5. Adds the user to the admin group
#   6. Generates access keys for the user
#
# Idempotent: Run again with a different username to add another admin.
#             Run again with the same username — skips what already exists.
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
  echo "Usage: $0 <bucket-prefix> <admin-username>"
  echo "Example: $0 acme-s3backup admin.john"
  exit 1
fi

BUCKET_PREFIX="$1"
ADMIN_USERNAME="$2"

# Derived names
GROUP_NAME="${BUCKET_PREFIX}-admin-group"
POLICY_NAME="${BUCKET_PREFIX}-admin-policy"
USER_NAME="${BUCKET_PREFIX}-admin-user-${ADMIN_USERNAME}"

# ---------------------------------------------------------------------------
# HELPERS
# ---------------------------------------------------------------------------
log()  { echo "[INFO]  $(date '+%H:%M:%S') — $*"; }
warn() { echo "[WARN]  $(date '+%H:%M:%S') — $*"; }

group_exists()  { aws iam get-group --group-name "$1" &>/dev/null; }
user_exists()   { aws iam get-user  --user-name  "$1" &>/dev/null; }

get_account_id() { aws sts get-caller-identity --query Account --output text; }

# ---------------------------------------------------------------------------
# PRE-FLIGHT
# ---------------------------------------------------------------------------
log "Starting admin user setup..."
ACCOUNT_ID=$(get_account_id)
log "AWS Account: $ACCOUNT_ID"
log "Region:      $AWS_REGION"
log "Prefix:      $BUCKET_PREFIX"
log "Admin User:  $USER_NAME"
echo ""

# ---------------------------------------------------------------------------
# STEP 1: CREATE ADMIN POLICY (if it doesn't exist)
# ---------------------------------------------------------------------------
# The admin policy grants two categories of permissions:
#
# (A) S3 — Full access to all buckets matching the prefix.
#     We use a wildcard on the prefix (acme-s3backup-*) so that as new
#     buckets are created, admins automatically have access without
#     updating this policy. This is the key scalability feature.
#
# (B) IAM — Scoped permissions to create/manage IAM entities that match
#     the prefix. This lets IT staff run create-bucket.sh to provision
#     new buckets and their IAM users/groups/policies, WITHOUT giving
#     them access to any other IAM entities in the account.
#
#     The Condition "iam:ResourceTag" is not used here because IAM
#     groups and policies don't support tags uniformly. Instead we
#     scope by resource ARN pattern using the naming convention.
# ---------------------------------------------------------------------------

POLICY_ARN="arn:aws:iam::${ACCOUNT_ID}:policy/${POLICY_NAME}"

POLICY_DOC=$(cat <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "S3FullAccessToPrefixedBuckets",
      "Effect": "Allow",
      "Action": "s3:*",
      "Resource": [
        "arn:aws:s3:::${BUCKET_PREFIX}-*",
        "arn:aws:s3:::${BUCKET_PREFIX}-*/*"
      ]
    },
    {
      "Sid": "S3ListAllBuckets",
      "Effect": "Allow",
      "Action": "s3:ListAllMyBuckets",
      "Resource": "arn:aws:s3:::*"
    },
    {
      "Sid": "IAMManagePrefixedUsers",
      "Effect": "Allow",
      "Action": [
        "iam:CreateUser",
        "iam:GetUser",
        "iam:DeleteUser",
        "iam:TagUser",
        "iam:CreateAccessKey",
        "iam:ListAccessKeys",
        "iam:DeleteAccessKey",
        "iam:AddUserToGroup",
        "iam:RemoveUserFromGroup"
      ],
      "Resource": "arn:aws:iam::${ACCOUNT_ID}:user/${BUCKET_PREFIX}-*"
    },
    {
      "Sid": "IAMManagePrefixedGroups",
      "Effect": "Allow",
      "Action": [
        "iam:CreateGroup",
        "iam:GetGroup",
        "iam:DeleteGroup",
        "iam:AddUserToGroup",
        "iam:RemoveUserFromGroup",
        "iam:AttachGroupPolicy",
        "iam:DetachGroupPolicy",
        "iam:ListAttachedGroupPolicies",
        "iam:ListGroupsForUser"
      ],
      "Resource": "arn:aws:iam::${ACCOUNT_ID}:group/${BUCKET_PREFIX}-*"
    },
    {
      "Sid": "IAMManagePrefixedPolicies",
      "Effect": "Allow",
      "Action": [
        "iam:CreatePolicy",
        "iam:GetPolicy",
        "iam:DeletePolicy",
        "iam:GetPolicyVersion",
        "iam:CreatePolicyVersion",
        "iam:ListPolicyVersions"
      ],
      "Resource": "arn:aws:iam::${ACCOUNT_ID}:policy/${BUCKET_PREFIX}-*"
    },
    {
      "Sid": "IAMListForConsole",
      "Effect": "Allow",
      "Action": [
        "iam:ListUsers",
        "iam:ListGroups",
        "iam:ListPolicies"
      ],
      "Resource": "*"
    },
    {
      "Sid": "STSGetCallerIdentity",
      "Effect": "Allow",
      "Action": "sts:GetCallerIdentity",
      "Resource": "*"
    },
    {
      "Sid": "CloudShellAccess",
      "Effect": "Allow",
      "Action": [
        "cloudshell:CreateEnvironment",
        "cloudshell:GetEnvironmentStatus",
        "cloudshell:StartEnvironment",
        "cloudshell:StopEnvironment",
        "cloudshell:DeleteEnvironment",
        "cloudshell:PutCredentials",
        "cloudshell:CreateSession",
        "cloudshell:GetFileDownloadUrls",
        "cloudshell:GetFileUploadUrls"
      ],
      "Resource": "*"
    }
  ]
}
EOF
)

if aws iam get-policy --policy-arn "$POLICY_ARN" &>/dev/null; then
  warn "Admin policy already exists: $POLICY_NAME"
else
  aws iam create-policy \
    --policy-name "$POLICY_NAME" \
    --policy-document "$POLICY_DOC" \
    --description "Admin policy for ${BUCKET_PREFIX} S3 backup infrastructure"
  log "Created admin policy: $POLICY_NAME"
fi

# ---------------------------------------------------------------------------
# STEP 2: CREATE ADMIN GROUP (if it doesn't exist)
# ---------------------------------------------------------------------------

if group_exists "$GROUP_NAME"; then
  warn "Admin group already exists: $GROUP_NAME"
else
  aws iam create-group --group-name "$GROUP_NAME"
  log "Created admin group: $GROUP_NAME"
fi

# Attach policy to group (idempotent)
aws iam attach-group-policy \
  --group-name "$GROUP_NAME" \
  --policy-arn "$POLICY_ARN"
log "Policy attached to group: $GROUP_NAME"

# ---------------------------------------------------------------------------
# STEP 3: CREATE ADMIN USER
# ---------------------------------------------------------------------------

if user_exists "$USER_NAME"; then
  warn "User already exists: $USER_NAME"
else
  aws iam create-user --user-name "$USER_NAME"
  log "Created user: $USER_NAME"
fi

# Add user to admin group (idempotent)
aws iam add-user-to-group \
  --group-name "$GROUP_NAME" \
  --user-name "$USER_NAME"
log "Added $USER_NAME to group $GROUP_NAME"

# ---------------------------------------------------------------------------
# STEP 4: ENABLE CONSOLE ACCESS
# ---------------------------------------------------------------------------
# Creates a login profile so the admin can sign into the AWS Console
# and use CloudShell to run create-bucket.sh.
# Password must be changed on first login (--password-reset-required).
# ---------------------------------------------------------------------------

TEMP_PASSWORD="${BUCKET_PREFIX}-Temp$(date +%s | tail -c 7)!"

if aws iam get-login-profile --user-name "$USER_NAME" &>/dev/null; then
  warn "Console access already enabled for $USER_NAME"
else
  aws iam create-login-profile \
    --user-name "$USER_NAME" \
    --password "$TEMP_PASSWORD" \
    --password-reset-required
  log "Console access enabled for $USER_NAME"

  CONSOLE_URL="https://${ACCOUNT_ID}.signin.aws.amazon.com/console"

  echo ""
  echo "=============================================="
  echo "  CONSOLE LOGIN — SHARE WITH ADMIN USER"
  echo "  (Password must be changed on first login)"
  echo "=============================================="
  echo ""
  echo "  Sign-in URL:      $CONSOLE_URL"
  echo "  Username:         $USER_NAME"
  echo "  Temp Password:    $TEMP_PASSWORD"
  echo ""
  echo "=============================================="
fi

# ---------------------------------------------------------------------------
# STEP 5: GENERATE ACCESS KEYS
# ---------------------------------------------------------------------------
# Check if user already has access keys (max 2 per user)
EXISTING_KEYS=$(aws iam list-access-keys --user-name "$USER_NAME" --query 'AccessKeyMetadata | length(@)' --output text)

if [ "$EXISTING_KEYS" -ge 2 ]; then
  warn "User $USER_NAME already has 2 access keys (AWS maximum). Skipping key creation."
  warn "Delete an existing key first if you need a new one:"
  warn "  aws iam delete-access-key --user-name $USER_NAME --access-key-id <key-id>"
else
  log "Generating access keys for $USER_NAME..."
  ACCESS_KEY_OUTPUT=$(aws iam create-access-key --user-name "$USER_NAME" --output json)

  ACCESS_KEY_ID=$(echo "$ACCESS_KEY_OUTPUT" | python3 -c "import sys,json; print(json.load(sys.stdin)['AccessKey']['AccessKeyId'])")
  SECRET_KEY=$(echo "$ACCESS_KEY_OUTPUT" | python3 -c "import sys,json; print(json.load(sys.stdin)['AccessKey']['SecretAccessKey'])")

  echo ""
  echo "=============================================="
  echo "  ACCESS KEYS — SAVE THESE NOW"
  echo "  (The secret key cannot be retrieved again)"
  echo "=============================================="
  echo ""
  echo "  User:             $USER_NAME"
  echo "  Access Key ID:    $ACCESS_KEY_ID"
  echo "  Secret Access Key: $SECRET_KEY"
  echo "  Region:           $AWS_REGION"
  echo ""
  echo "  Configure AWS CLI:"
  echo "    aws configure --profile ${USER_NAME}"
  echo "    # Enter the Access Key ID and Secret Access Key above"
  echo "    # Default region: $AWS_REGION"
  echo "    # Default output: json"
  echo ""
  echo "=============================================="
fi

echo ""
log "Admin setup complete."
log ""
log "To add another admin, run:"
log "  $0 $BUCKET_PREFIX another.admin"
log ""
log "To create a bucket (run as this admin user), use:"
log "  ./create-bucket.sh $BUCKET_PREFIX server001"
