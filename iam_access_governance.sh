#!/bin/bash
set -euo pipefail

########################################
# CONFIGURACIÓN GENERAL
########################################
CONFIG_FILE="${CONFIG_FILE:-./config.env}"
if [ -f "$CONFIG_FILE" ]; then
  # shellcheck disable=SC1090
  source "$CONFIG_FILE"
fi

PROFILE="${PROFILE:-AWSProdCyberArchitect}"
SLACK_WEBHOOK_URL="${SLACK_WEBHOOK_URL:-}"
LOOKBACK_DAYS="${LOOKBACK_DAYS:-180}"
CLOUDTRAIL_MAX_RESULTS="${CLOUDTRAIL_MAX_RESULTS:-50}"
CLOUDTRAIL_REGIONS="${CLOUDTRAIL_REGIONS:-}"
SIMULATE_EFFECTIVE="${SIMULATE_EFFECTIVE:-true}"
SIMULATE_ONLY_USED="${SIMULATE_ONLY_USED:-true}"

usage() {
  echo "Usage: $0 [-p aws_profile] [-l lookback_days]" >&2
}

while getopts ":p:l:h" opt; do
  case "$opt" in
    p) PROFILE="$OPTARG" ;;
    l) LOOKBACK_DAYS="$OPTARG" ;;
    h) usage; exit 0 ;;
    *) usage; exit 1 ;;
  esac
done

YEAR=$(date +%Y)
MONTH=$(date +%m)
QUARTER=$(( (10#$MONTH - 1) / 3 + 1 ))

OUTPUT="IAM_Access_Review_${YEAR}-Q${QUARTER}.xlsx"
JSON_OUTPUT="IAM_Access_Review_${YEAR}-Q${QUARTER}.json"
BASELINE_DIR="baseline"
mkdir -p "$BASELINE_DIR"

WORKDIR=$(mktemp -d)

START_TIME=$(python3 - <<PY
from datetime import datetime, timedelta, timezone
print((datetime.now(timezone.utc) - timedelta(days=int("${LOOKBACK_DAYS}"))).isoformat())
PY
)
END_TIME=$(python3 - <<PY
from datetime import datetime, timezone
print(datetime.now(timezone.utc).isoformat())
PY
)

if [ -z "$CLOUDTRAIL_REGIONS" ]; then
  REGIONS_RAW=$(aws ec2 describe-regions \
    --profile "$PROFILE" \
    --query 'Regions[].RegionName' \
    --output text 2>/dev/null || true)
  if [ -n "$REGIONS_RAW" ]; then
    CLOUDTRAIL_REGIONS=$(echo "$REGIONS_RAW" | tr '\t' ',')
  fi
fi

########################################
# DEPENDENCIAS
########################################
command -v jq >/dev/null || { echo "❌ jq requerido"; exit 1; }

python3 - <<'EOF'
import sys, subprocess
try:
    import openpyxl
except ImportError:
    subprocess.check_call([sys.executable,"-m","pip","install","--user","openpyxl"])
EOF

########################################
# SLACK
########################################
send_slack () {
  local SEV="$1"; local MSG="$2"
  [ -z "$SLACK_WEBHOOK_URL" ] && return
  curl -s -X POST -H 'Content-type: application/json' \
    --data "{\"text\":\"[$SEV] $MSG\"}" \
    "$SLACK_WEBHOOK_URL" >/dev/null
}

########################################
# IDENTIDAD DE EJECUCIÓN
########################################
CALLER_ARN=$(aws sts get-caller-identity --profile "$PROFILE" --query Arn --output text)
EXEC_USER=$(echo "$CALLER_ARN" | awk -F'/' '{print $NF}')

########################################
# VALIDACIÓN CLOUDTRAIL
########################################
TRAILS=$(aws cloudtrail describe-trails \
  --profile "$PROFILE" \
  --query 'trailList[].Name' \
  --output text 2>/dev/null || true)
if [ -z "$TRAILS" ]; then
  send_slack "WARNING" "No CloudTrail trails found; report may be incomplete"
else
  for t in $TRAILS; do
    LOGGING=$(aws cloudtrail get-trail-status \
      --profile "$PROFILE" \
      --name "$t" \
      --query 'IsLogging' \
      --output text 2>/dev/null || true)
    if [ "$LOGGING" != "True" ]; then
      send_slack "WARNING" "CloudTrail trail not logging: $t"
    fi
  done
fi

########################################
# CREDENTIAL REPORT
########################################
aws iam generate-credential-report --profile "$PROFILE" >/dev/null 2>&1 || true
sleep 5
aws iam get-credential-report \
  --profile "$PROFILE" \
  --query 'Content' \
  --output text | base64 --decode > "$WORKDIR/cred.csv"

ACTIVE_USERS=$(python3 - <<PY
import csv
from datetime import datetime, timezone, timedelta
cutoff = datetime.now(timezone.utc) - timedelta(days=int("${LOOKBACK_DAYS}"))

def parse_dt(value):
    if not value or value in ("N/A","no_information","not_supported"):
        return None
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%S+00:00").replace(tzinfo=timezone.utc)
    except Exception:
        return None

users = []
with open("$WORKDIR/cred.csv") as f:
    for row in csv.DictReader(f):
        u = row.get("user")
        if not u or u == "<root_account>":
            continue
        dates = [
            row.get("password_last_used"),
            row.get("access_key_1_last_used_date"),
            row.get("access_key_2_last_used_date"),
        ]
        if any((parse_dt(d) and parse_dt(d) >= cutoff) for d in dates):
            users.append(u)
print(" ".join(users))
PY
)
if [ -z "$ACTIVE_USERS" ]; then
  ACTIVE_USERS=$(aws iam list-users --profile "$PROFILE" --query 'Users[].UserName' --output text)
fi

########################################
# USUARIOS Y GRUPOS
########################################
echo "User,Group" > "$WORKDIR/groups.csv"

for u in $ACTIVE_USERS; do
  echo "$u,User::$u" >> "$WORKDIR/groups.csv"
  gs=$(aws iam list-groups-for-user \
    --profile "$PROFILE" \
    --user-name "$u" \
    --query 'Groups[].GroupName' \
    --output text)
  if [ -z "$gs" ]; then
    echo "$u,No-Group" >> "$WORKDIR/groups.csv"
  else
    for g in $gs; do echo "$u,Group::$g" >> "$WORKDIR/groups.csv"; done
  fi
done
########################################
# ADMIN EFECTIVO (POLICY SIMULATION)
########################################
ACCOUNT_ID=$(aws sts get-caller-identity --profile "$PROFILE" --query Account --output text)
ADMIN_ACTIONS=(iam:CreateUser iam:AttachUserPolicy iam:PutUserPolicy sts:AssumeRole ec2:RunInstances s3:PutBucketPolicy)

echo "User,Effective_Admin" > "$WORKDIR/admin.csv"

for u in $ACTIVE_USERS; do
  res=$(aws iam simulate-principal-policy \
    --profile "$PROFILE" \
    --policy-source-arn arn:aws:iam::$ACCOUNT_ID:user/$u \
    --action-names "${ADMIN_ACTIONS[@]}" \
    --query 'EvaluationResults[].EvalDecision' \
    --output text 2>/dev/null || true)

  if echo "$res" | grep -qi allowed; then
    echo "$u,Yes" >> "$WORKDIR/admin.csv"
    send_slack "CRITICAL" "User $u has EFFECTIVE ADMIN privileges"
  else
    echo "$u,No" >> "$WORKDIR/admin.csv"
  fi
done

########################################
# BASELINE + DRIFT
########################################
BASELINE_FILE="$BASELINE_DIR/IAM_Baseline_${YEAR}-Q${QUARTER}.json"

python3 <<EOF
import csv, json
b={}
for r in csv.DictReader(open("$WORKDIR/cred.csv")):
    b[r["user"]]={"pwd":r["password_enabled"],"mfa":r["mfa_active"]}
for r in csv.DictReader(open("$WORKDIR/admin.csv")):
    b.setdefault(r["User"],{})["admin"]=r["Effective_Admin"]
json.dump(b,open("$BASELINE_FILE","w"),indent=2)
EOF

PREV=$(ls baseline/IAM_Baseline_*.json 2>/dev/null | grep -v "$BASELINE_FILE" | tail -1 || true)
if [ -n "$PREV" ]; then
  DRIFT=$(python3 <<EOF
import json
o=json.load(open("$PREV")); n=json.load(open("$BASELINE_FILE"))
a=set(n)-set(o); r=set(o)-set(n)
c=[u for u in n if u in o and n[u]!=o[u]]
out=[]
if a: out.append("ADDED: "+", ".join(sorted(a)))
if r: out.append("REMOVED: "+", ".join(sorted(r)))
if c: out.append("CHANGED: "+", ".join(sorted(c)))
print("\\n".join(out))
EOF
)
  [ -n "$DRIFT" ] && send_slack "WARNING" "$DRIFT"
fi

########################################
# GRUPOS USADOS
########################################
USED_GROUPS=$(cut -d',' -f2 "$WORKDIR/groups.csv" | tail -n +2 | grep -v No-Group | sort -u)

########################################
# ACCIONES PERMITIDAS POR POLICY
########################################
echo "Group,Policy,Action" > "$WORKDIR/policy_actions.csv"

extract_actions () {
  local doc="$1"
  echo "$doc" | jq -r '
    ( .Statement | if type=="array" then .[] else . end )
    | select(.Effect=="Allow")
    | .Action
    | if type=="array" then .[] else . end
  '
}

# Group policies (attached + inline)
for g in $USED_GROUPS; do
  case "$g" in
    Group::*) gname=${g#Group::} ;;
    *) continue ;;
  esac

  aws iam list-attached-group-policies \
    --profile "$PROFILE" \
    --group-name "$gname" \
    --query 'AttachedPolicies[].PolicyArn' \
    --output text | tr '\t' '\n' | while read arn; do
      [ -z "$arn" ] && continue
      pname=$(basename "$arn")
      ver=$(aws iam get-policy \
        --profile "$PROFILE" \
        --policy-arn "$arn" \
        --query 'Policy.DefaultVersionId' \
        --output text)
      doc=$(aws iam get-policy-version \
        --profile "$PROFILE" \
        --policy-arn "$arn" \
        --version-id "$ver" \
        --query 'PolicyVersion.Document' \
        --output json)
      extract_actions "$doc" | while read act; do
        echo "$g,$pname,$act" >> "$WORKDIR/policy_actions.csv"
      done
  done

  aws iam list-group-policies \
    --profile "$PROFILE" \
    --group-name "$gname" \
    --query 'PolicyNames[]' \
    --output text | tr '\t' '\n' | while read pname; do
      [ -z "$pname" ] && continue
      doc=$(aws iam get-group-policy \
        --profile "$PROFILE" \
        --group-name "$gname" \
        --policy-name "$pname" \
        --query 'PolicyDocument' \
        --output json)
      extract_actions "$doc" | while read act; do
        echo "$g,$pname,$act" >> "$WORKDIR/policy_actions.csv"
      done
  done
done

# User policies (attached + inline)
for u in $ACTIVE_USERS; do
  usub="User::$u"
  aws iam list-attached-user-policies \
    --profile "$PROFILE" \
    --user-name "$u" \
    --query 'AttachedPolicies[].PolicyArn' \
    --output text | tr '\t' '\n' | while read arn; do
      [ -z "$arn" ] && continue
      pname=$(basename "$arn")
      ver=$(aws iam get-policy \
        --profile "$PROFILE" \
        --policy-arn "$arn" \
        --query 'Policy.DefaultVersionId' \
        --output text)
      doc=$(aws iam get-policy-version \
        --profile "$PROFILE" \
        --policy-arn "$arn" \
        --version-id "$ver" \
        --query 'PolicyVersion.Document' \
        --output json)
      extract_actions "$doc" | while read act; do
        echo "$usub,$pname,$act" >> "$WORKDIR/policy_actions.csv"
      done
  done

  aws iam list-user-policies \
    --profile "$PROFILE" \
    --user-name "$u" \
    --query 'PolicyNames[]' \
    --output text | tr '\t' '\n' | while read pname; do
      [ -z "$pname" ] && continue
      doc=$(aws iam get-user-policy \
        --profile "$PROFILE" \
        --user-name "$u" \
        --policy-name "$pname" \
        --query 'PolicyDocument' \
        --output json)
      extract_actions "$doc" | while read act; do
        echo "$usub,$pname,$act" >> "$WORKDIR/policy_actions.csv"
      done
  done
done

# Role policies (attached + inline)
# Only for roles observed in CloudTrail within the review window
USED_ROLES=$(python3 - <<PY
import json, subprocess
cmd = [
  "aws","cloudtrail","lookup-events",
  "--profile","$PROFILE",
  "--max-results","$CLOUDTRAIL_MAX_RESULTS",
  "--start-time","$START_TIME",
  "--end-time","$END_TIME",
  "--lookup-attributes","AttributeKey=EventName,AttributeValue=AssumeRole"
]
regions=[r for r in "$CLOUDTRAIL_REGIONS".split(",") if r]
roles=set()
def extract_role(event):
    identity = event.get("userIdentity", {})
    arn = identity.get("arn", "")
    issuer = identity.get("sessionContext", {}).get("sessionIssuer", {})
    if issuer.get("type") == "Role" and issuer.get("userName"):
        return issuer.get("userName")
    if "assumed-role/" in arn:
        return arn.split("assumed-role/")[1].split("/")[0]
    return None

def fetch_events(region=None):
    next_token=None
    while True:
        call = cmd[:] + (["--region", region] if region else []) + (["--next-token", next_token] if next_token else [])
        resp = json.loads(subprocess.check_output(call))
        for e in resp.get("Events", []):
            d = json.loads(e.get("CloudTrailEvent","{}"))
            role = extract_role(d)
            if role:
                roles.add(role)
        next_token = resp.get("NextToken")
        if not next_token:
            break

if regions:
    for r in regions:
        fetch_events(r)
else:
    fetch_events()

print(" ".join(sorted(roles)))
PY
)

for r in $USED_ROLES; do
  rsub="Role::$r"
  aws iam list-attached-role-policies \
    --profile "$PROFILE" \
    --role-name "$r" \
    --query 'AttachedPolicies[].PolicyArn' \
    --output text | tr '\t' '\n' | while read arn; do
      [ -z "$arn" ] && continue
      pname=$(basename "$arn")
      ver=$(aws iam get-policy \
        --profile "$PROFILE" \
        --policy-arn "$arn" \
        --query 'Policy.DefaultVersionId' \
        --output text)
      doc=$(aws iam get-policy-version \
        --profile "$PROFILE" \
        --policy-arn "$arn" \
        --version-id "$ver" \
        --query 'PolicyVersion.Document' \
        --output json)
      extract_actions "$doc" | while read act; do
        echo "$rsub,$pname,$act" >> "$WORKDIR/policy_actions.csv"
      done
  done

  aws iam list-role-policies \
    --profile "$PROFILE" \
    --role-name "$r" \
    --query 'PolicyNames[]' \
    --output text | tr '\t' '\n' | while read pname; do
      [ -z "$pname" ] && continue
      doc=$(aws iam get-role-policy \
        --profile "$PROFILE" \
        --role-name "$r" \
        --policy-name "$pname" \
        --query 'PolicyDocument' \
        --output json)
      extract_actions "$doc" | while read act; do
        echo "$rsub,$pname,$act" >> "$WORKDIR/policy_actions.csv"
      done
  done
done

########################################
########################################
# CLOUDTRAIL – ACCIONES REALES
########################################
python3 cloudtrail_permission_diff.py \
  --profile "$PROFILE" \
  --groups "$WORKDIR/groups.csv" \
  --policy-actions "$WORKDIR/policy_actions.csv" \
  --start-time "$START_TIME" \
  --end-time "$END_TIME" \
  --max-results "$CLOUDTRAIL_MAX_RESULTS" \
  ${CLOUDTRAIL_REGIONS:+--regions "$CLOUDTRAIL_REGIONS"} \
  --output "$WORKDIR/permission_diff.csv" \
  --output-json "$WORKDIR/permission_diff.json" \
  ${SIMULATE_EFFECTIVE:+--simulate-effective --account-id "$ACCOUNT_ID"} \
  ${SIMULATE_ONLY_USED:+--simulate-only-used}

########################################
# EXCEL FINAL
########################################
python3 <<EOF
import csv
from openpyxl import Workbook
from openpyxl.styles import Font
from datetime import datetime

SERVICE_PATTERNS=["lpv2","lpv3","-ses","sns"]

wb=Workbook()

# IAM_Users
ws=wb.active
ws.title="IAM_Users"
with open("$WORKDIR/cred.csv") as f:
    r=csv.reader(f)
    ws.append(next(r)+["Account_Type","Effective_Admin"])
    for c in ws[1]: c.font=Font(bold=True)
    admin=dict((u,a) for u,a in csv.reader(open("$WORKDIR/admin.csv")) if u!="User")
    for row in r:
        user=row[0].lower()
        pwd=row[7]=="true"; mfa=row[8]=="true"
        ak1=row[9]=="true"; ak2=row[14]=="true"
        has_keys=ak1 or ak2
        if (not pwd and not mfa and has_keys) or any(p in user for p in SERVICE_PATTERNS):
            t="Service"
        elif pwd or mfa or not has_keys:
            t="Human"
        else:
            t="Uncertain"
        ws.append(row+[t,admin.get(row[0],"Unknown")])

# IAM_User_Groups
wg=wb.create_sheet("IAM_User_Groups")
for i,r in enumerate(csv.reader(open("$WORKDIR/groups.csv"))):
    wg.append(r)
    if i==0:
        for c in wg[1]: c.font=Font(bold=True)

# Permission_Diff (si existe)
try:
    with open("$WORKDIR/permission_diff.csv") as f:
        wd=wb.create_sheet("Permission_Diff")
        r=csv.reader(f)
        wd.append(next(r))
        for c in wd[1]: c.font=Font(bold=True)
        for row in r:
            wd.append(row)
except FileNotFoundError:
    pass

# Management_Review
wm=wb.create_sheet("Management_Review")
wm.append(["Item","Value"])
wm.append(["Review Period","$YEAR-Q$QUARTER"])
wm.append(["Executed By","$EXEC_USER"])
wm.append(["Generated At",datetime.utcnow().strftime("%Y-%m-%d")])
wm.append(["Model","IAM Governance + CloudTrail Least Privilege"])

wb.save("$OUTPUT")
EOF

########################################
# FINAL
########################################
if [ -f "$WORKDIR/permission_diff.json" ]; then
  cp "$WORKDIR/permission_diff.json" "$JSON_OUTPUT"
fi
rm -rf "$WORKDIR"
send_slack "INFO" "IAM Governance + Least Privilege review completed: $OUTPUT"
echo "✅ Archivo generado: $OUTPUT"
echo "✅ Archivo generado: $JSON_OUTPUT"