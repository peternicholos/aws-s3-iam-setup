#!/usr/bin/env bash
# =============================================================================
# AWS S3 + IAM Automated Setup for Multi-Business-Unit Isolation
# =============================================================================
# Purpose:  Create one S3 bucket per business unit, an Admin group with full
#           access to ALL buckets, and per-unit IAM groups + placeholder users
#           with least-privilege access scoped to their own bucket only.
#
# Runtime:  AWS CloudShell (Bash + AWS CLI v2 pre-installed)
# Usage:    chmod +x setup_s3_iam.sh && ./setup_s3_iam.sh
#
# Configuration: Edit the BUSINESS_UNITS array and BUCKET_PREFIX below.
# =============================================================================

set -euo pipefail

# ---------------------------------------------------------------------------
# CONFIGURATION — edit these to match your environment
# ---------------------------------------------------------------------------

# Prefix applied to every bucket: <PREFIX>-<unit-name>
# Example: "acme-corp" produces buckets like acme-corp-finance, acme-corp-hr
BUCKET_PREFIX="acme-corp"

# AWS region for bucket creation
AWS_REGION="us-east-1"

# Business unit identifiers (lowercase, no spaces — used in bucket names,
# IAM group names, and usernames). Add as many as needed.
BUSINESS_UNITS=(
  "finance"
  "hr"
  "marketing"
  "sales"
  "engineering"
  "legal"
  "operations"
  "support"
  "logistics"
  "research"
)

# Admin IAM group name — members get full access to ALL unit buckets
ADMIN_GROUP_NAME="S3-Admin-Group"

# Naming conventions (derived automatically)
# IAM group per unit : S3-Unit-<UnitName>
# IAM user per unit  : s3-user-<unitname>
# IAM policy per unit: S3-Policy-<UnitName>

# ---------------------------------------------------------------------------
# HELPER FUNCTIONS
# ---------------------------------------------------------------------------

log()   { echo "[INFO]  $(date '+%H:%M:%S') — $*"; }
warn()  { echo "[WARN]  $(date '+%H:%M:%S') — $*"; }
error() { echo "[ERROR] $(date '+%H:%M:%S') — $*" >&2; }

# Check if an IAM entity already exists to make the script re-runnable
group_exists() { aws iam get-group --group-name "$1" &>/dev/null; }
user_exists()  { aws iam get-user  --user-name  "$1" &>/dev/null; }
policy_exists() {
  local acct_id
  acct_id=$(aws sts get-caller-identity --query Account --output text)
  aws iam get-policy --policy-arn "arn:aws:iam::${acct_id}:policy/$1" &>/dev/null
}

get_account_id() { aws sts get-caller-identity --query Account --output text; }

# ---------------------------------------------------------------------------
# PRE-FLIGHT CHECKS
# ---------------------------------------------------------------------------

log "Running pre-flight checks..."

# Verify AWS CLI is available
if ! command -v aws &>/dev/null; then
  error "AWS CLI not found. Run this script in AWS CloudShell."
  exit 1
fi

# Verify caller identity
CALLER_IDENTITY=$(aws sts get-caller-identity --output json 2>/dev/null) || {
  error "Unable to determine AWS identity. Check your credentials."
  exit 1
}
ACCOUNT_ID=$(echo "$CALLER_IDENTITY" | python3 -c "import sys,json; print(json.load(sys.stdin)['Account'])")
log "AWS Account: $ACCOUNT_ID"
log "Region:      $AWS_REGION"
log "Units:       ${#BUSINESS_UNITS[@]}"
echo ""

# ---------------------------------------------------------------------------
# STEP 1: CREATE S3 BUCKETS
# ---------------------------------------------------------------------------
# Each bucket is named <BUCKET_PREFIX>-<unit>.
# Block Public Access is enabled by default (security best practice).
# Versioning is enabled for data protection.
# ---------------------------------------------------------------------------

log "=== STEP 1: Creating S3 Buckets ==="

for unit in "${BUSINESS_UNITS[@]}"; do
  BUCKET_NAME="${BUCKET_PREFIX}-${unit}"

  if aws s3api head-bucket --bucket "$BUCKET_NAME" 2>/dev/null; then
    warn "Bucket already exists: $BUCKET_NAME — skipping creation."
  else
    log "Creating bucket: $BUCKET_NAME"

    # CreateBucket in us-east-1 must NOT include LocationConstraint
    if [ "$AWS_REGION" = "us-east-1" ]; then
      aws s3api create-bucket \
        --bucket "$BUCKET_NAME" \
        --region "$AWS_REGION"
    else
      aws s3api create-bucket \
        --bucket "$BUCKET_NAME" \
        --region "$AWS_REGION" \
        --create-bucket-configuration LocationConstraint="$AWS_REGION"
    fi

    # Block all public access — defense in depth
    aws s3api put-public-access-block \
      --bucket "$BUCKET_NAME" \
      --public-access-block-configuration \
        "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"

    # Enable versioning for accidental-delete protection
    aws s3api put-bucket-versioning \
      --bucket "$BUCKET_NAME" \
      --versioning-configuration Status=Enabled

    log "  -> Created and secured: $BUCKET_NAME"
  fi
done

echo ""

# ---------------------------------------------------------------------------
# STEP 2: CREATE ADMIN IAM GROUP + POLICY
# ---------------------------------------------------------------------------
# The Admin group gets s3:* on ALL buckets created by this script.
# Policy is attached to the GROUP (not individual users) so that:
#   - Adding/removing admins is a single group-membership change.
#   - We avoid per-user policy sprawl (IAM limits: 10 managed policies/user).
#   - Auditing is simpler — one policy to review, one group to enumerate.
# ---------------------------------------------------------------------------

log "=== STEP 2: Creating Admin Group ==="

if group_exists "$ADMIN_GROUP_NAME"; then
  warn "Admin group already exists: $ADMIN_GROUP_NAME — skipping creation."
else
  aws iam create-group --group-name "$ADMIN_GROUP_NAME"
  log "Created IAM group: $ADMIN_GROUP_NAME"
fi

# Build the resource ARN list for all unit buckets
ADMIN_RESOURCE_ARNS=""
for unit in "${BUSINESS_UNITS[@]}"; do
  BUCKET_NAME="${BUCKET_PREFIX}-${unit}"
  # We need both the bucket ARN (for ListBucket) and bucket/* (for object ops)
  ADMIN_RESOURCE_ARNS="${ADMIN_RESOURCE_ARNS}\"arn:aws:s3:::${BUCKET_NAME}\",\"arn:aws:s3:::${BUCKET_NAME}/*\","
done
# Remove trailing comma
ADMIN_RESOURCE_ARNS="${ADMIN_RESOURCE_ARNS%,}"

ADMIN_POLICY_NAME="S3-Admin-FullAccess-AllUnits"

# Build the admin policy document
# -------------------------------------------------------------------------
# WHY s3:* on specific resources (not Resource: "*"):
#   - Granting s3:* on "*" would give access to ALL S3 buckets in the account,
#     including ones outside this project. By listing only our unit buckets we
#     follow least-privilege even for admins.
# WHY a single policy with all ARNs (not one policy per bucket):
#   - Keeps us well under the 6,144-char inline-policy limit for 100+ units
#     by using a single managed policy. Managed policies allow up to 6,144
#     chars per version and can be shared across groups.
# -------------------------------------------------------------------------
ADMIN_POLICY_DOC=$(cat <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AdminFullS3AccessToAllUnitBuckets",
      "Effect": "Allow",
      "Action": "s3:*",
      "Resource": [${ADMIN_RESOURCE_ARNS}]
    },
    {
      "Sid": "AdminListAllBuckets",
      "Effect": "Allow",
      "Action": "s3:ListAllMyBuckets",
      "Resource": "arn:aws:s3:::*"
    }
  ]
}
EOF
)

ADMIN_POLICY_ARN="arn:aws:iam::${ACCOUNT_ID}:policy/${ADMIN_POLICY_NAME}"

if policy_exists "$ADMIN_POLICY_NAME"; then
  warn "Admin policy already exists — updating to latest version."
  aws iam create-policy-version \
    --policy-arn "$ADMIN_POLICY_ARN" \
    --policy-document "$ADMIN_POLICY_DOC" \
    --set-as-default 2>/dev/null || warn "Policy version limit reached; delete old versions if needed."
else
  aws iam create-policy \
    --policy-name "$ADMIN_POLICY_NAME" \
    --policy-document "$ADMIN_POLICY_DOC" \
    --description "Full S3 access to all business-unit buckets managed by setup script"
  log "Created managed policy: $ADMIN_POLICY_NAME"
fi

# Attach policy to admin group (idempotent — no error if already attached)
aws iam attach-group-policy \
  --group-name "$ADMIN_GROUP_NAME" \
  --policy-arn "$ADMIN_POLICY_ARN"
log "Attached admin policy to group: $ADMIN_GROUP_NAME"

echo ""

# ---------------------------------------------------------------------------
# STEP 3: CREATE PER-UNIT IAM GROUPS, POLICIES, AND USERS
# ---------------------------------------------------------------------------
# For each business unit we create:
#   1. An IAM group  : S3-Unit-<UnitName>
#   2. A managed policy scoped to ONLY that unit's bucket
#   3. A placeholder IAM user added to the group
#
# POLICY DESIGN CHOICES (see EXPLANATION.md for full rationale):
#
# - Policies attach to GROUPS, not users:
#     Groups let you add/remove users without touching policies. This avoids
#     the IAM limit of 10 managed policies per user and keeps auditing simple.
#
# - Resource-level permissions (not conditions):
#     Each policy's Resource field lists only the unit's bucket ARN. This is
#     more explicit, auditable, and performant than using s3:prefix conditions.
#
# - No IAM roles for unit access:
#     Roles add complexity (AssumeRole trust policies, session duration, STS
#     calls) that is unnecessary when straightforward group-based access works.
#     Roles are better suited for cross-account access or temporary elevation.
#
# - Separate policy per unit (not one giant policy):
#     Keeps each policy tiny and readable. AWS allows 5,000 managed policies
#     per account (soft limit, can be raised), so 100-200 units is well within
#     limits. Each policy stays under 500 chars — far below the 6,144 cap.
# ---------------------------------------------------------------------------

log "=== STEP 3: Creating Per-Unit Groups, Policies, and Users ==="

for unit in "${BUSINESS_UNITS[@]}"; do
  BUCKET_NAME="${BUCKET_PREFIX}-${unit}"
  # Capitalize first letter for IAM naming convention
  UNIT_CAPITALIZED="$(echo "${unit:0:1}" | tr '[:lower:]' '[:upper:]')${unit:1}"

  GROUP_NAME="S3-Unit-${UNIT_CAPITALIZED}"
  POLICY_NAME="S3-Policy-${UNIT_CAPITALIZED}"
  USER_NAME="s3-user-${unit}"

  log "--- Processing unit: ${unit} ---"

  # -- 3a. Create IAM group for this unit --
  if group_exists "$GROUP_NAME"; then
    warn "  Group exists: $GROUP_NAME"
  else
    aws iam create-group --group-name "$GROUP_NAME"
    log "  Created group: $GROUP_NAME"
  fi

  # -- 3b. Create scoped policy --
  # -----------------------------------------------------------------------
  # Statement breakdown:
  #
  # ListAllMyBuckets (Sid: ListBuckets):
  #   Required so the AWS Console bucket list renders. Without it, users see
  #   "Access Denied" before they can even navigate to their bucket.
  #   Resource must be arn:aws:s3:::* (API requirement — cannot be scoped).
  #   This only reveals bucket NAMES, not contents.
  #
  # ListBucket (Sid: ListOwnBucket):
  #   Allows listing objects inside the unit's bucket only.
  #   Resource: the bucket ARN (not bucket/*).
  #
  # GetObject + PutObject (Sid: ReadWriteOwnBucket):
  #   Allows reading and uploading objects in the unit's bucket.
  #   Resource: bucket/* (object-level ARN).
  #   We intentionally OMIT s3:DeleteObject — units cannot delete. Admins can.
  #
  # Explicit Deny (Sid: DenyAllOtherBuckets):
  #   Denies ALL S3 actions on any bucket that is NOT this unit's bucket.
  #   Uses NotResource so the deny applies to everything except the allowed
  #   bucket. This is a safety net — even if someone accidentally attaches
  #   a broader policy, the explicit deny wins (AWS deny-overrides-allow).
  #   We exclude s3:ListAllMyBuckets from the deny so console listing works.
  # -----------------------------------------------------------------------
  UNIT_POLICY_DOC=$(cat <<EOF
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
      "Sid": "ListOwnBucket",
      "Effect": "Allow",
      "Action": "s3:ListBucket",
      "Resource": "arn:aws:s3:::${BUCKET_NAME}"
    },
    {
      "Sid": "ReadWriteOwnBucket",
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:PutObject"
      ],
      "Resource": "arn:aws:s3:::${BUCKET_NAME}/*"
    },
    {
      "Sid": "DenyAllOtherBuckets",
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

  UNIT_POLICY_ARN="arn:aws:iam::${ACCOUNT_ID}:policy/${POLICY_NAME}"

  if policy_exists "$POLICY_NAME"; then
    warn "  Policy exists: $POLICY_NAME — updating."
    aws iam create-policy-version \
      --policy-arn "$UNIT_POLICY_ARN" \
      --policy-document "$UNIT_POLICY_DOC" \
      --set-as-default 2>/dev/null || warn "  Policy version limit; delete old versions if needed."
  else
    aws iam create-policy \
      --policy-name "$POLICY_NAME" \
      --policy-document "$UNIT_POLICY_DOC" \
      --description "Scoped S3 access for business unit: ${unit}"
    log "  Created policy: $POLICY_NAME"
  fi

  # Attach policy to unit group
  aws iam attach-group-policy \
    --group-name "$GROUP_NAME" \
    --policy-arn "$UNIT_POLICY_ARN"
  log "  Attached policy to group: $GROUP_NAME"

  # -- 3c. Create placeholder IAM user and add to group --
  if user_exists "$USER_NAME"; then
    warn "  User exists: $USER_NAME"
  else
    aws iam create-user --user-name "$USER_NAME"
    log "  Created user: $USER_NAME"
  fi

  # Add user to their unit group (idempotent)
  aws iam add-user-to-group \
    --group-name "$GROUP_NAME" \
    --user-name "$USER_NAME"
  log "  Added $USER_NAME to group $GROUP_NAME"

  echo ""
done

# ---------------------------------------------------------------------------
# STEP 4: VERIFICATION SUMMARY
# ---------------------------------------------------------------------------

log "=== STEP 4: Verification Summary ==="
echo ""
echo "=============================================="
echo "  SETUP COMPLETE"
echo "=============================================="
echo ""
echo "Account ID:    $ACCOUNT_ID"
echo "Region:        $AWS_REGION"
echo "Bucket Prefix: $BUCKET_PREFIX"
echo "Units Created: ${#BUSINESS_UNITS[@]}"
echo ""
echo "Admin Group:   $ADMIN_GROUP_NAME"
echo "Admin Policy:  $ADMIN_POLICY_NAME"
echo ""
echo "----------------------------------------------"
printf "%-20s %-25s %-20s\n" "UNIT" "GROUP" "USER"
echo "----------------------------------------------"
for unit in "${BUSINESS_UNITS[@]}"; do
  UNIT_CAP="$(echo "${unit:0:1}" | tr '[:lower:]' '[:upper:]')${unit:1}"
  printf "%-20s %-25s %-20s\n" "$unit" "S3-Unit-${UNIT_CAP}" "s3-user-${unit}"
done
echo "----------------------------------------------"
echo ""
echo "NEXT STEPS:"
echo "  1. Add real admin users to '$ADMIN_GROUP_NAME'"
echo "     aws iam add-user-to-group --group-name $ADMIN_GROUP_NAME --user-name <admin-user>"
echo ""
echo "  2. Create access keys for unit users (or use SSO/federation):"
echo "     aws iam create-access-key --user-name s3-user-<unit>"
echo ""
echo "  3. Test isolation (see EXPLANATION.md for test commands)"
echo ""
log "Done."
