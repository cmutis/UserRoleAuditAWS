import argparse, csv, subprocess, json, fnmatch
from collections import defaultdict

parser = argparse.ArgumentParser()
parser.add_argument("--profile", required=True)
parser.add_argument("--groups", required=True)
parser.add_argument("--policy-actions", required=True)
parser.add_argument("--output", required=True)
parser.add_argument("--output-json", required=False)
parser.add_argument("--start-time", required=False)
parser.add_argument("--end-time", required=False)
parser.add_argument("--regions", required=False)
parser.add_argument("--max-results", required=False, default="50")
parser.add_argument("--simulate-effective", action="store_true")
parser.add_argument("--simulate-only-used", action="store_true")
parser.add_argument("--account-id", required=False)
args = parser.parse_args()

if args.simulate_effective and not args.account_id:
    raise SystemExit("--account-id is required when --simulate-effective is set")

# User -> Subjects (Group::X, User::Y)
user_groups = defaultdict(set)
with open(args.groups) as f:
    r = csv.DictReader(f)
    for row in r:
        if row["Group"] != "No-Group":
            user_groups[row["User"]].add(row["Group"])

# Allowed actions per subject
allowed = defaultdict(set)
with open(args.policy_actions) as f:
    r = csv.DictReader(f)
    for row in r:
        allowed[row["Group"]].add(row["Action"].lower())

# CloudTrail events
cmd = [
    "aws",
    "cloudtrail",
    "lookup-events",
    "--profile",
    args.profile,
    "--max-results",
    str(args.max_results),
]
if args.start_time:
    cmd += ["--start-time", args.start_time]
if args.end_time:
    cmd += ["--end-time", args.end_time]

regions = [r for r in (args.regions or "").split(",") if r]


def fetch_events(region=None):
    collected = []
    next_token = None
    while True:
        call = cmd[:] + (["--region", region] if region else []) + (
            ["--next-token", next_token] if next_token else []
        )
        resp = json.loads(subprocess.check_output(call))
        collected.extend(resp.get("Events", []))
        next_token = resp.get("NextToken")
        if not next_token:
            break
    return collected


events = []
if regions:
    for r in regions:
        events.extend(fetch_events(r))
else:
    events = fetch_events()

used = defaultdict(set)
used_subjects = set()


def normalize_subject(name, prefix):
    return f"{prefix}::{name}"


def subject_to_arn(subject, account_id):
    if subject.startswith("User::"):
        return f"arn:aws:iam::{account_id}:user/{subject.split('::',1)[1]}"
    if subject.startswith("Role::"):
        return f"arn:aws:iam::{account_id}:role/{subject.split('::',1)[1]}"
    return None


def role_from_identity(identity):
    issuer = identity.get("sessionContext", {}).get("sessionIssuer", {})
    if issuer.get("type") == "Role" and issuer.get("userName"):
        return issuer.get("userName")
    arn = identity.get("arn", "")
    # arn:aws:sts::ACCOUNT:assumed-role/RoleName/Session
    if not arn or "assumed-role/" not in arn:
        return None
    try:
        return arn.split("assumed-role/")[1].split("/")[0]
    except Exception:
        return None


def is_used(allowed_action, used_actions):
    if not used_actions:
        return False
    pattern = allowed_action
    for ua in used_actions:
        # Either allowed is wildcard matching used, or used is wildcard matching allowed
        if fnmatch.fnmatchcase(ua, pattern) or fnmatch.fnmatchcase(pattern, ua):
            return True
    return False


def chunked(items, size):
    for i in range(0, len(items), size):
        yield items[i : i + size]


def simulate_effective(subject, actions):
    arn = subject_to_arn(subject, args.account_id)
    if not arn:
        return None
    plain = [a for a in actions if "*" not in a and "?" not in a]
    wildcard = {a for a in actions if a not in plain}
    if not plain:
        return {"allowed": set(), "denied": set(), "wildcard": wildcard}
    allowed_actions = set()
    denied_actions = set()
    for chunk in chunked(plain, 100):
        call = [
            "aws",
            "iam",
            "simulate-principal-policy",
            "--profile",
            args.profile,
            "--policy-source-arn",
            arn,
            "--action-names",
            *chunk,
        ]
        try:
            resp = json.loads(subprocess.check_output(call))
        except subprocess.CalledProcessError:
            return None
        for r in resp.get("EvaluationResults", []):
            name = (r.get("EvalActionName") or "").lower()
            decision = (r.get("EvalDecision") or "").lower()
            if decision == "allowed":
                allowed_actions.add(name)
            else:
                denied_actions.add(name)
    return {"allowed": allowed_actions, "denied": denied_actions, "wildcard": wildcard}


for e in events:
    d = json.loads(e["CloudTrailEvent"])
    identity = d.get("userIdentity", {})
    user = identity.get("userName")
    role = role_from_identity(identity)
    src = d.get("eventSource")
    name = d.get("eventName")
    if not user or not src or not name:
        # If this is an assumed role without userName, map by role
        if not role or not src or not name:
            continue
    action = f"{src.split('.')[0]}:{name}".lower()
    if user:
        subj = normalize_subject(user, "User")
        used[subj].add(action)
        used_subjects.add(subj)
        for g in user_groups.get(user, []):
            used[g].add(action)
    if role:
        subj = normalize_subject(role, "Role")
        used[subj].add(action)
        used_subjects.add(subj)

# Simulate effective permissions for users/roles when enabled
simulated = {}
if args.simulate_effective:
    for subject, actions in allowed.items():
        if not (subject.startswith("User::") or subject.startswith("Role::")):
            continue
        if args.simulate_only_used and subject not in used_subjects:
            continue
        simulated[subject] = simulate_effective(subject, actions)

rows = []
for g in allowed:
    sim = simulated.get(g)
    for act in sorted(allowed[g]):
        used_flag = "Yes" if is_used(act, used[g]) else "No"
        effective = "Unknown"
        if sim is not None:
            if act in sim["wildcard"]:
                effective = "Unknown"
            elif act in sim["allowed"]:
                effective = "Yes"
            elif act in sim["denied"]:
                effective = "No"
            else:
                effective = "No"
        if effective == "No":
            rec = "Remove (Not allowed by effective policy)"
        elif used_flag == "Yes":
            rec = "Keep"
        else:
            rec = "Candidate for removal"
        rows.append([g, act, "Yes", used_flag, effective, rec])

with open(args.output, "w", newline="") as f:
    w = csv.writer(f)
    w.writerow(["Group", "Action", "Allowed", "Used", "Effective", "Recommendation"])
    w.writerows(rows)

if args.output_json:
    with open(args.output_json, "w") as f:
        json.dump(
            [
                dict(
                    Group=r[0],
                    Action=r[1],
                    Allowed=r[2],
                    Used=r[3],
                    Effective=r[4],
                    Recommendation=r[5],
                )
                for r in rows
            ],
            f,
            indent=2,
        )
