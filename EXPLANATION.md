# AWS S3 + IAM Multi-Business-Unit Setup — Design Explanation

## Overview

This document explains the architectural and security decisions behind `setup_s3_iam.sh`. The script provisions one S3 bucket per business unit, an Admin IAM group with full cross-bucket access, and per-unit IAM groups with least-privilege policies.

---

## 1. Why Policies Attach to Groups, Not Users

**Decision:** Every IAM policy is attached to a group. Users inherit permissions solely through group membership.

**Rationale:**
- **Scalability:** Adding a new employee to a unit means one `add-user-to-group` call — no policy edits needed.
- **IAM limits:** AWS allows only 10 managed policies per user. Attaching to groups avoids hitting this ceiling.
- **Auditability:** Reviewing who has access to a bucket = listing group members. No need to inspect each user's individual policies.
- **Offboarding:** Removing a user from a group instantly revokes all unit access.

---

## 2. Resource-Level Permissions vs. Condition Keys

**Decision:** Policies use explicit `Resource` ARNs (e.g., `arn:aws:s3:::acme-corp-finance/*`) rather than wildcard resources with `aws:username` or `s3:prefix` conditions.

**Rationale:**
- **Clarity:** Anyone reading the policy sees exactly which bucket is allowed — no mental evaluation of condition logic needed.
- **Performance:** AWS evaluates resource-scoped policies faster than condition-based ones at scale.
- **Safety:** Condition keys like `aws:username` can be fragile — they depend on the calling principal type. If access is later granted via a role or federated identity, `aws:username` may be empty, causing unexpected denials or (worse) unintended access.

**Why not `aws:PrincipalArn`?**
`aws:PrincipalArn` is useful in resource-based policies (bucket policies, role trust policies) where you need to identify the *caller*. For identity-based policies (attached to groups/users), the principal is already implied — the policy only applies to its attachment target. Using `aws:PrincipalArn` in identity-based policies adds complexity with no security gain.

---

## 3. Explicit Deny as a Safety Net

**Decision:** Each unit policy includes a `Deny` statement using `NotResource` that blocks all S3 actions (except `ListAllMyBuckets`) on any bucket other than the unit's own.

**Rationale:**
- AWS policy evaluation: an explicit **Deny always overrides Allow**, regardless of where the Allow comes from.
- If someone accidentally attaches an overly broad policy (e.g., `AmazonS3FullAccess`) to a unit user, the explicit deny still blocks cross-bucket access.
- This is a defense-in-depth measure — it costs nothing and prevents a common misconfiguration from becoming a data breach.

---

## 4. Why Groups Instead of Roles for Unit Access

**Decision:** Unit users access their bucket directly through group-inherited policies, not via `sts:AssumeRole`.

**Rationale:**
- **Simplicity:** Roles require trust policies, session duration configuration, and STS calls. For permanent, same-account access this adds complexity without benefit.
- **User experience:** Console users would need to switch roles to access their bucket — confusing for non-technical business unit staff.
- **When to use roles instead:** If you later need cross-account access (unit in Account A accessing bucket in Account B), or temporary privilege escalation, roles become the right tool.

---

## 5. One Policy Per Unit (Not One Giant Policy)

**Decision:** Each unit gets its own managed IAM policy (~400 chars each) rather than one policy listing all 100+ unit ARNs.

**Rationale:**
- **Readability:** Each policy is self-contained and reviewable in seconds.
- **Modification:** Changing one unit's permissions doesn't risk breaking others.
- **Limits:** AWS allows 5,000 customer-managed policies per account (soft limit, raisable). Even at 200 units this uses only 4% of the limit.
- **Admin policy exception:** The Admin group uses a single policy with all bucket ARNs because admins need uniform access everywhere. This policy stays under the 6,144-character limit even at 100+ units (each ARN pair adds ~60 chars).

---

## 6. s3:ListAllMyBuckets — Why It's Broad

**Decision:** Every policy (admin and unit) grants `s3:ListAllMyBuckets` on `arn:aws:s3:::*`.

**Rationale:**
- The S3 API requires this action on a wildcard resource — you cannot scope it to specific buckets (AWS limitation).
- Without it, the AWS Console shows "Access Denied" before users can even navigate to their bucket.
- This only reveals bucket **names**, not contents. Object access is still fully scoped.

---

## 7. Omitting s3:DeleteObject for Unit Users

**Decision:** Unit users can `GetObject` and `PutObject` but cannot `DeleteObject`.

**Rationale:**
- Least privilege: most business units need to upload and download files, not delete them.
- Combined with bucket versioning (enabled by the script), even accidental overwrites are recoverable.
- If a specific unit needs delete permissions, add `s3:DeleteObject` to that unit's policy — no other unit is affected.

---

## 8. Scaling Past 100 Units

The design handles 100+ units with minimal policy bloat because:

| Concern | How it's handled |
|---|---|
| Policy count | One per unit = linear growth, well within the 5,000 limit |
| Admin policy size | All ARNs in one policy; ~60 bytes per unit = ~6KB at 100 units (under 6,144-char limit). If you exceed ~90 units, split into two admin policy attachments. |
| Script runtime | Each unit adds ~5 API calls; 100 units = ~500 calls, completes in under 10 minutes in CloudShell |
| Adding a new unit | Append one entry to `BUSINESS_UNITS` array and re-run. The script is idempotent — existing resources are skipped. |
| Removing a unit | Delete the user, detach/delete the policy, delete the group, and optionally delete/empty the bucket. (Not automated to prevent accidental data loss.) |

---

## 9. Testing Isolation

After running the script, verify with these commands:

```bash
# Create access key for a test user
aws iam create-access-key --user-name s3-user-finance

# Configure a named CLI profile with those keys
aws configure --profile test-finance
# Enter the AccessKeyId and SecretAccessKey from above

# TEST 1: User can list their own bucket
aws s3 ls s3://acme-corp-finance --profile test-finance
# Expected: success (list of objects or empty)

# TEST 2: User can upload to their own bucket
echo "test" > /tmp/test.txt
aws s3 cp /tmp/test.txt s3://acme-corp-finance/test.txt --profile test-finance
# Expected: success

# TEST 3: User can download from their own bucket
aws s3 cp s3://acme-corp-finance/test.txt /tmp/downloaded.txt --profile test-finance
# Expected: success

# TEST 4: User CANNOT access another unit's bucket
aws s3 ls s3://acme-corp-hr --profile test-finance
# Expected: Access Denied

# TEST 5: User CANNOT delete objects
aws s3 rm s3://acme-corp-finance/test.txt --profile test-finance
# Expected: Access Denied

# Clean up test access key
aws iam delete-access-key --user-name s3-user-finance --access-key-id <key-id>
```

---

## 10. Security Checklist

- [x] All buckets have Block Public Access enabled
- [x] Bucket versioning enabled (accidental delete/overwrite recovery)
- [x] Explicit deny prevents cross-bucket access even if broader policies are attached
- [x] No wildcard (`*`) in Resource fields (except `ListAllMyBuckets` — AWS requirement)
- [x] No inline policies — all managed for version tracking and reuse
- [x] Delete permission excluded for unit users (least privilege)
- [x] Script is idempotent — safe to re-run without duplicating resources
