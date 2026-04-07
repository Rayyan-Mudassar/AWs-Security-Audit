import boto3
import json
from datetime import datetime, timezone

# ── helpers ──────────────────────────────────────────────────────────────────

def days_since(dt):
    return (datetime.now(timezone.utc) - dt).days

# ── checks ───────────────────────────────────────────────────────────────────

def audit_s3():
    s3 = boto3.client('s3')
    results = []
    buckets = s3.list_buckets().get('Buckets', [])

    for bucket in buckets:
        name = bucket['Name']
        findings = []

        # Public access check
        try:
            pub = s3.get_public_access_block(Bucket=name)
            cfg = pub['PublicAccessBlockConfiguration']
            if not all(cfg.values()):
                findings.append("FAIL - Public access block not fully enabled")
            else:
                findings.append("PASS - Public access blocked")
        except Exception:
            findings.append("FAIL - No public access block configured")

        # Versioning check
        try:
            ver = s3.get_bucket_versioning(Bucket=name)
            status = ver.get('Status', 'Disabled')
            if status == 'Enabled':
                findings.append("PASS - Versioning enabled")
            else:
                findings.append("FAIL - Versioning not enabled")
        except Exception as e:
            findings.append(f"ERROR - Versioning check failed: {e}")

        # Encryption check
        try:
            s3.get_bucket_encryption(Bucket=name)
            findings.append("PASS - Server-side encryption enabled")
        except s3.exceptions.ClientError:
            findings.append("FAIL - No server-side encryption configured")
        except Exception as e:
            findings.append(f"ERROR - Encryption check failed: {e}")

        results.append({"bucket": name, "findings": findings})

    return results


def audit_iam():
    iam = boto3.client('iam')
    results = []
    users = iam.list_users().get('Users', [])

    for user in users:
        username = user['UserName']
        findings = []

        # MFA check
        mfa_devices = iam.list_mfa_devices(UserName=username).get('MFADevices', [])
        if mfa_devices:
            findings.append("PASS - MFA enabled")
        else:
            findings.append("FAIL - No MFA device attached")

        # Admin policy check
        attached = iam.list_attached_user_policies(UserName=username).get('AttachedPolicies', [])
        admin = any(p['PolicyName'] == 'AdministratorAccess' for p in attached)
        if admin:
            findings.append("FAIL - AdministratorAccess policy attached directly to user")
        else:
            findings.append("PASS - No direct admin policy")

        # Access key age check
        keys = iam.list_access_keys(UserName=username).get('AccessKeyMetadata', [])
        for key in keys:
            age = days_since(key['CreateDate'])
            kid = key['AccessKeyId']
            if age > 90:
                findings.append(f"FAIL - Access key {kid} is {age} days old (>90 days)")
            else:
                findings.append(f"PASS - Access key {kid} is {age} days old")

        results.append({"user": username, "findings": findings})

    return results


def audit_security_groups():
    ec2 = boto3.client('ec2')
    results = []
    sgs = ec2.describe_security_groups().get('SecurityGroups', [])

    for sg in sgs:
        sgid = sg['GroupId']
        sgname = sg['GroupName']
        findings = []

        for rule in sg.get('IpPermissions', []):
            from_port = rule.get('FromPort', -1)
            to_port = rule.get('ToPort', -1)
            for ip_range in rule.get('IpRanges', []):
                if ip_range.get('CidrIp') == '0.0.0.0/0':
                    if from_port <= 22 <= to_port:
                        findings.append("FAIL - SSH (port 22) open to 0.0.0.0/0")
                    if from_port <= 3389 <= to_port:
                        findings.append("FAIL - RDP (port 3389) open to 0.0.0.0/0")
                    if from_port == -1:
                        findings.append("FAIL - All traffic allowed from 0.0.0.0/0")

        if not findings:
            findings.append("PASS - No dangerous open ports to public internet")

        results.append({"sg_id": sgid, "sg_name": sgname, "findings": findings})

    return results


def audit_cloudtrail():
    ct = boto3.client('cloudtrail')
    findings = []
    trails = ct.describe_trails().get('trailList', [])

    if not trails:
        findings.append("FAIL - No CloudTrail trails configured")
    else:
        for trail in trails:
            name = trail['Name']
            status = ct.get_trail_status(Name=trail['TrailARN'])
            if status.get('IsLogging'):
                findings.append(f"PASS - Trail '{name}' is active and logging")
            else:
                findings.append(f"FAIL - Trail '{name}' exists but logging is OFF")

    return findings


# ── report ────────────────────────────────────────────────────────────────────

def generate_report():
    report_lines = []
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    report_lines.append("=" * 60)
    report_lines.append("       AWS SECURITY AUDIT REPORT")
    report_lines.append(f"       Generated: {timestamp}")
    report_lines.append("=" * 60)

    # S3
    report_lines.append("\n[ S3 BUCKETS ]\n")
    for item in audit_s3():
        report_lines.append(f"  Bucket: {item['bucket']}")
        for f in item['findings']:
            report_lines.append(f"    → {f}")
        report_lines.append("")

    # IAM
    report_lines.append("\n[ IAM USERS ]\n")
    for item in audit_iam():
        report_lines.append(f"  User: {item['user']}")
        for f in item['findings']:
            report_lines.append(f"    → {f}")
        report_lines.append("")

    # Security Groups
    report_lines.append("\n[ SECURITY GROUPS ]\n")
    for item in audit_security_groups():
        report_lines.append(f"  SG: {item['sg_name']} ({item['sg_id']})")
        for f in item['findings']:
            report_lines.append(f"    → {f}")
        report_lines.append("")

    # CloudTrail
    report_lines.append("\n[ CLOUDTRAIL ]\n")
    for f in audit_cloudtrail():
        report_lines.append(f"  → {f}")

    report_lines.append("\n" + "=" * 60)
    report_lines.append("END OF REPORT")
    report_lines.append("=" * 60)

    report_text = "\n".join(report_lines)

    # Save to file
    filename = f"aws_security_audit_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    with open(filename, 'w', encoding='utf-8') as f:
        f.write(report_text)

    print(report_text)
    print(f"\nReport saved to: {filename}")


if __name__ == "__main__":
    generate_report()
