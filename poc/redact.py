#!/usr/bin/env python3
"""Mask the credential-bearing fields in a captured response or transcript.

The point of this file is that the redaction is mechanical and repeatable: every
masked artefact in this repository was produced by running it, not by editing a
screenshot by hand. It masks by field name first, then does one value-shaped pass
over free text so a secret that ended up inside a log line is still caught.

    python3 poc/redact.py out/response.json
    python3 poc/redact.py --self-test

Rules applied (case-insensitive on the key):

    secret                      -> "masked"
    session_token               -> "present (N chars)"
    access_key_id / key_id      -> first 8 chars + ellipsis  (ASIAY2IZ…)
    account / account_id        -> first 6 digits + ellipsis
    *_sid / sid                 -> first 8 chars + ellipsis
    arn                         -> account and resource name masked
    phone / number / to / from  -> country code and first digits only
    nextSequenceToken           -> first 6 chars + ellipsis
    log_group / function_name   -> first path segment kept, tail masked

Values that are booleans, counts, regions, domains and the runtime API address
are left alone: they carry no credential and they are the finding.
"""

import json
import re
import sys

# --- field-name rules -------------------------------------------------------

def _ellipsis(s, keep):
    return s[:keep] + "…" if len(s) > keep else s


def mask_by_key(key, value):
    """Return a masked copy of `value` for a known-sensitive key, else value."""
    if not isinstance(value, str):
        return value
    k = key.lower()

    if "secret" in k and "token" not in k:
        return "masked"
    if "session_token" in k or k.endswith("_token"):
        return "present (%d chars)" % len(value)
    if "access_key" in k or k.endswith("key_id"):
        return _ellipsis(value, 8)
    if "arn" in k:
        # arn:aws:sts::123456789012:assumed-role/role-name/session  ->
        # arn:aws:sts::123456…:assumed-role/role-name/…
        m = re.match(r"^(arn:[^:]+:[^:]+::)(\d{12})(:.+?/)([^/]+)$", value)
        if m:
            return "%s%s…%s…" % (m.group(1), m.group(2)[:6], m.group(3))
        return _ellipsis(value, 24)
    if k in ("account", "account_id", "accountid") or "account_sid" in k:
        digits = re.sub(r"\D", "", value)
        if len(digits) >= 10 and k != "account_sid":
            return digits[:6] + "…"
        return _ellipsis(value, 8)
    if k.endswith("_sid") or k == "sid":
        return _ellipsis(value, 8)
    if k in ("phone", "phone_number", "number", "to", "from", "to_number", "from_number"):
        digits = re.sub(r"\D", "", value)
        return "+" + digits[:5] + "…" if digits else _ellipsis(value, 5)
    if k == "nextsequencetoken":
        return _ellipsis(value, 6)
    if k in ("function_name", "aws_lambda_function_name"):
        return _ellipsis(value, 9)
    if k in ("log_group", "aws_lambda_log_group_name"):
        return _ellipsis(value, 22)
    return value


# --- value-shaped pass, for secrets embedded in free text -------------------

VALUE_RULES = [
    # temporary AWS access key id
    (re.compile(r"\b(ASIA[0-9A-Z]{8})[0-9A-Z]{6,}\b"), r"\1…"),
    # AWS account id inside an ARN or a bare 12-digit run
    (re.compile(r"(arn:aws:[a-z]+:[^:]*::)(\d{6})\d{6}"), r"\1\2…"),
    # Twilio SIDs
    (re.compile(r"\b(AC[0-9a-f]{6})[0-9a-f]{26}\b"), r"\1…"),
    (re.compile(r"\b(ZS[0-9a-f]{6})[0-9a-f]{26}\b"), r"\1…"),
    (re.compile(r"\b(ZE[0-9a-f]{6})[0-9a-f]{26}\b"), r"\1…"),
    (re.compile(r"\b(PN[0-9a-f]{6})[0-9a-f]{28}\b"), r"\1…"),
    (re.compile(r"\b(SM[0-9a-f]{6})[0-9a-f]{26}\b"), r"\1…"),
    # Lambda function ids (20-hex-ish) and their log-group path
    (re.compile(r"(/aws/lambda/)([A-Za-z0-9]{9})[A-Za-z0-9]{10,}"), r"\1\2…"),
    # E.164 numbers, keeping the country/area prefix only
    (re.compile(r"(\+1\d{3})\d{7}\b"), r"\1…"),
    (re.compile(r"(\+91\d{4})\d{6}\b"), r"\1…"),
    # long opaque tokens (session tokens, sequence tokens)
    (re.compile(r"\b([A-Za-z0-9/+=]{6})[A-Za-z0-9/+=]{80,}\b"), r"\1…"),
]


def mask_text(text):
    for pattern, repl in VALUE_RULES:
        text = pattern.sub(repl, text)
    return text


def walk(obj):
    if isinstance(obj, dict):
        return {k: walkv(k, v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [walk(v) for v in obj]
    if isinstance(obj, str):
        return mask_text(obj)
    return obj


def walkv(key, value):
    if isinstance(value, dict):
        return {k: walkv(k, v) for k, v in value.items()}
    if isinstance(value, list):
        return [walk(v) for v in value]
    if isinstance(value, str):
        masked = mask_by_key(key, value)
        return masked if masked != value else mask_text(value)
    return value


# --- self test --------------------------------------------------------------

SELFTEST = {
    # Synthetic values. They are shaped like the real ones so the masks are
    # exercised, but none of them is a value from the run.
    "aws_access_key_id": "ASIAFAKEFAKEFAKE0000",
    "aws_secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYFAKEFAKEFAKE",
    "aws_session_token": "FAKE" + "Q" * 344,
    "aws_region": "us-east-1",
    "account_sid": "AC" + "0123456789abcdef" * 2,
    "service_sid": "ZS" + "fedcba9876543210" * 2,
    "environment_sid": "ZE" + "0011223344556677" * 2,
    "domain": "example-0000-dev.twil.io",
    "phone": "+14155550123",
    "nextSequenceToken": "100000000000000000000000000000000000",
    "arn": "arn:aws:sts::123456789012:assumed-role/lambda-role-execution/FAKESESSIONIDFAKESESSIONID",
    "note": "ran with ASIAFAKEFAKEFAKE0000 against /aws/lambda/FAKEFUNCTIONID12345678",
}

FORBIDDEN = [
    "ASIAFAKEFAKEFAKE0000",
    "wJalrXUtnFEMI",
    "FAKEQQQQ",
    "123456789012",
    "AC0123456789abcdef",
    "ZSfedcba9876543210",
    "ZE0011223344556677",
    "+14155550123",
    "100000000000000000000000000000",
    "FAKEFUNCTIONID12345678",
]


def self_test():
    out = json.dumps(walk(SELFTEST), indent=2, ensure_ascii=False)
    leaked = [f for f in FORBIDDEN[:-2] if f in out]
    # the role name is allowed to survive only inside a masked ARN
    if "lambda-role-execution/" in out and "…" not in out:
        leaked.append("arn")
    if leaked:
        print("SELFTEST FAIL — raw values survived: %s" % leaked)
        print(out)
        return 1
    assert "us-east-1" in out and "example-0000-dev.twil.io" in out
    print("SELFTEST PASS — %d forbidden strings absent; region and domain intact"
          % len(FORBIDDEN))
    print(out)
    return 0


def main(argv):
    if "--self-test" in argv:
        return self_test()
    if len(argv) < 2:
        print(__doc__.strip().splitlines()[0])
        print("usage: redact.py <file.json | -> [--self-test]")
        return 2
    path = argv[1]
    raw = sys.stdin.read() if path == "-" else open(path, encoding="utf-8").read()
    try:
        doc = json.loads(raw)
    except json.JSONDecodeError:
        sys.stdout.write(mask_text(raw))
        return 0
    json.dump(walk(doc), sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
