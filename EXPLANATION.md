# AWS S3 Backup Infrastructure — Design Explanation

## Overview

Two scripts manage an S3 backup infrastructure for 100+ business units:

- create-admin-user.sh — Sets up admin users who can manage the infrastructure
- create-bucket.sh — Provisions a single bucket + IAM user on demand

IT staff run these scripts using admin IAM credentials (not root). Each server's backup software gets its own isolated IAM user with access keys scoped to only its bucket.

---

## Architecture

```
Root Account (you)
  |
  +-- create-admin-user.sh (run once per admin)
  |     |
  |     +-- acme-s3backup-group-admin
  |     |     +-- acme-s3backup-policy-admin (S3 + scoped IAM)
  |     |
  |     +-- acme-s3backup-user-admin.john --> group-admin
  |     +-- acme-s3backup-user-admin.jane --> group-admin
  |
  +-- create-bucket.sh (run by admin, once per server)
        |
        +-- acme-s3backup-server001 (S3 bucket)
        |     +-- acme-s3backup-group-server001
        |     |     +-- acme-s3backup-policy-server001 (scoped to this bucket)
        |     +-- acme-s3backup-user-server001 --> group-server001
        |
        +-- acme-s3backup-server002 (S3 bucket)
              +-- acme-s3backup-group-server002
              |     +-- acme-s3backup-policy-server002 (scoped to this bucket)
              +-- acme-s3backup-user-server002 --> group-server002
```

---

## Workflow

Step 1 (you, one-time):
  Run create-admin-user.sh from root/admin to create the first IT admin.
  Give the access keys to the IT staff member.

Step 2 (IT staff, as needed):
  IT staff configure AWS CLI with their admin keys.
  Run create-bucket.sh for each new server.
  Enter the generated access keys into the backup software.

Step 3 (adding more admins):
  Run create-admin-user.sh again with a different username.
  New admin is added to the existing admin group.

---

## Policy Design Decisions

### 1. Admin Policy — Why Scoped IAM Permissions?

The admin policy grants S3 full access PLUS limited IAM permissions. The IAM permissions are scoped by ARN pattern:

  arn:aws:iam::*:user/acme-s3backup-*
  arn:aws:iam::*:group/acme-s3backup-*
  arn:aws:iam::*:policy/acme-s3backup-*

This means IT staff can create/manage backup users and groups but CANNOT:
- Create arbitrary IAM users (only acme-s3backup-* named ones)
- Modify other policies or groups in the account
- Escalate their own privileges
- Access non-backup S3 buckets

This is the principle of least privilege applied to the admin role itself.

### 2. Why Wildcard in Admin S3 Policy?

The admin S3 statement uses:
  Resource: arn:aws:s3:::acme-s3backup-*

This wildcard means new buckets created by create-bucket.sh are automatically accessible to admins without updating the admin policy. This is the key scalability feature — you never touch the admin policy again.

### 3. Why Policies Attach to Groups, Not Users?

- Adding a new person = one add-user-to-group call
- Removing a person = one remove-user-from-group call
- AWS limits: 10 managed policies per user. Groups avoid this limit.
- Auditing: "who has access?" = list group members

### 4. Why Resource-Level Permissions, Not Conditions?

Each bucket policy uses explicit Resource ARNs, not aws:username or s3:prefix conditions.

- Clearer to read and audit
- No risk of condition key being empty (which happens with federated/role-based access)
- AWS evaluates resource-scoped policies faster

### 5. Why Explicit Deny on Other Buckets?

Each bucket user's policy includes:
  Effect: Deny
  NotAction: s3:ListAllMyBuckets
  NotResource: [own-bucket, own-bucket/*]

In AWS, explicit Deny ALWAYS wins over Allow. If someone accidentally attaches a broad policy (like AmazonS3FullAccess) to a backup user, the explicit deny still blocks cross-bucket access. Defense in depth at zero cost.

### 6. Why DeleteObject is Included for Backup Users?

Backup software typically needs to manage retention — deleting old backups to free space. Combined with bucket versioning (enabled by default), deleted objects are recoverable for 30+ days. If you want admins-only deletion, remove s3:DeleteObject from the bucket policy template.

### 7. Why Multipart Upload Permissions?

Backup files can be large (database dumps, disk images). AWS requires multipart upload for files over 5GB. Without ListMultipartUploadParts and AbortMultipartUpload, interrupted uploads leave orphaned parts that accumulate cost.

### 8. Scaling Past 100 Units

| Concern | How it's handled |
|---|---|
| Policy count | One per bucket, linear growth, well within AWS 5,000 limit |
| Admin policy size | Uses wildcard (acme-s3backup-*), never needs updating |
| Adding a server | IT staff runs one command: ./create-bucket.sh acme-s3backup server101 |
| Removing a server | Delete user, detach/delete policy, delete group, empty/delete bucket |
| Script runtime | ~5 API calls per bucket, completes in under 15 seconds |

### 9. Why No Roles?

IAM roles are designed for temporary credentials and cross-account access. Your backup software runs on servers outside AWS and needs persistent access keys. IAM users with access keys are the correct tool here. Roles would add complexity (AssumeRole calls, session expiry, STS token refresh) with no benefit.

---

## Testing Isolation

After creating an admin and a bucket:

```bash
# As admin — create two test buckets
./create-bucket.sh acme-s3backup testserver01
./create-bucket.sh acme-s3backup testserver02

# Configure CLI profile for testserver01's user
aws configure --profile test01
# Enter access key and secret from create-bucket.sh output

# TEST 1: Can access own bucket
echo "hello" > /tmp/test.txt
aws s3 cp /tmp/test.txt s3://acme-s3backup-testserver01/test.txt --profile test01
aws s3 ls s3://acme-s3backup-testserver01 --profile test01
# Expected: success

# TEST 2: Cannot access other bucket
aws s3 ls s3://acme-s3backup-testserver02 --profile test01
# Expected: Access Denied

# TEST 3: Cannot create IAM resources (not an admin)
aws iam create-user --user-name test-escalation --profile test01
# Expected: Access Denied
```

---

## Security Checklist

- [x] All buckets have Block Public Access enabled
- [x] Bucket versioning enabled (backup recovery + accidental delete protection)
- [x] Explicit deny prevents cross-bucket access
- [x] Admin IAM permissions scoped to prefix-named entities only
- [x] IT staff cannot escalate privileges or access non-backup resources
- [x] Backup users have minimum permissions for backup operations
- [x] Multipart upload supported for large files
- [x] Scripts are idempotent — safe to re-run
- [x] Access keys generated and displayed once (secret not retrievable after)
