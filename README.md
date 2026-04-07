# 🔍 AWS Security Auditor — Automated Account Security Audit with Python & boto3

## 📌 The Story

After building and deploying my serverless notes app on AWS, I had S3 buckets, IAM users, EC2 security groups, and various services running across my account. Everything was working — but I had no idea if any of it was actually secure.

That's when I asked myself: **what would a real security engineer do at this point?**

They wouldn't manually click through the AWS console checking every setting. They would write a script, run it against the account, and get a report. So that's exactly what I built.

---

## 🛠️ What It Does

A Python script using boto3 that connects to an AWS account, audits it across 4 critical security areas, and generates a timestamped report saved as a `.txt` file.

**The script checks:**

| Area | Checks |
|---|---|
| S3 Buckets | Public access block, versioning, server-side encryption |
| IAM Users | MFA enabled, direct admin policy, access key age (>90 days) |
| Security Groups | SSH (port 22) open to 0.0.0.0/0, RDP (port 3389) open to 0.0.0.0/0, all traffic open |
| CloudTrail | Trail exists and is actively logging |

> ⚠️ **Note:** The IAM user `rayyan-cli` requires AdministratorAccess to run this audit script — it needs read permissions across S3, IAM, EC2, and CloudTrail. This is a temporary CLI account used for AWS labs. MFA is enforced on the root account.

---

## 🔴 First Run — What I Found

Running the script for the first time exposed real issues in my account:

```
[ S3 BUCKETS ]
  Bucket: lambda-hosting12
    → PASS - Public access blocked
    → FAIL - Versioning not enabled        ← no recovery if file deleted
    → PASS - Server-side encryption enabled

  Bucket: my-own-static-bucket112
    → PASS - Public access blocked
    → FAIL - Versioning not enabled        ← same issue
    → PASS - Server-side encryption enabled

[ IAM USERS ]
  User: rayyan-cli
    → FAIL - No MFA device attached        ← temporary account, MFA on root
    → FAIL - AdministratorAccess policy attached directly to user  ← needed to run audit
    → PASS - Access key is 0 days old

[ SECURITY GROUPS ]
  → PASS - No dangerous open ports        ← clean

[ CLOUDTRAIL ]
  → FAIL - No CloudTrail trails configured  ← CRITICAL: zero visibility into account activity
```

**The most serious finding was CloudTrail being completely disabled.** If someone had compromised the account at that moment, there would be zero logs — no way to know what they accessed, what they changed, or when it happened. That's a critical visibility gap for any AWS account.

S3 versioning being disabled was also a real risk — without it, if a file gets accidentally deleted or overwritten, it's gone permanently with no way to recover it.

---

## ✅ Remediation — What I Fixed

After identifying the threats, I fixed them one by one and ran the audit again:

**Fixed:**
- Enabled versioning on all S3 buckets
- Created a CloudTrail trail (`management-events`) with S3 logging enabled

**Accepted risk:**
- MFA not attached to `rayyan-cli` — this is a temporary lab account. MFA is enabled on the root account which is the higher priority.
- AdministratorAccess on `rayyan-cli` — required to run the audit script across all services.

---

## 🟢 Second Run — Clean Report

```
[ S3 BUCKETS ]
  Bucket: aws-cloudtrail-logs-544446317554-ca46d56d
    → PASS - Public access blocked
    → PASS - Versioning enabled
    → PASS - Server-side encryption enabled

  Bucket: lambda-hosting12
    → PASS - Public access blocked
    → PASS - Versioning enabled
    → PASS - Server-side encryption enabled

  Bucket: my-own-static-bucket112
    → PASS - Public access blocked
    → PASS - Versioning enabled
    → PASS - Server-side encryption enabled

[ CLOUDTRAIL ]
  → PASS - Trail 'management-events' is active and logging
```

All S3 buckets green. CloudTrail active. The account now has proper logging and data protection in place.

---

## 🚀 How to Run

**Requirements:**
- Python 3.x
- boto3 installed (`pip install boto3`)
- AWS credentials configured (`aws configure`)
- IAM user with AdministratorAccess (needed to audit all services)

**Run:**
```bash
python audit.py
```

The script prints the report to terminal and saves it as:
```
aws_security_audit_YYYYMMDD_HHMMSS.txt
```

---

## 💡 Key Learnings

- CloudTrail should be the first thing enabled in any AWS account — without it you are operating blind
- S3 versioning is cheap insurance — always enable it on buckets that hold important data
- A security audit is only useful if you act on the findings — finding issues and ignoring them is worse than not looking
- Automating security checks with boto3 is far more reliable than manual console reviews, especially as an account grows

---

## 📁 Project Structure

```
├── audit.py                              # The audit script
├── aws_security_audit_before.txt         # First run — findings
├── aws_security_audit_after.txt          # Second run — after remediation
└── README.md
```
