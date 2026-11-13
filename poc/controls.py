#!/usr/bin/env python3
"""The negative controls for the credential.

One credential, three ways of presenting it. A finding is a differential, and
this is the differential that makes "the credentials work" mean something:

    1. key + secret, session token REMOVED   -> must fail
    2. key + secret + fabricated token       -> must fail
    3. key + secret + real session token     -> must succeed

If (1) succeeded, what was captured would be a long-lived key and the severity
would be different. It fails, because the value is an assumed-role credential:
`ASIA` prefix, an expiry, and a token that is part of the signature.

    python3 poc/controls.py
"""

import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
from offhost_check import aws, env_for, load  # noqa: E402
from redact import mask_text  # noqa: E402


def main():
    doc, creds = load()
    results = []

    # 1. session token removed
    rc, out = aws(env_for(doc, creds, drop_session_token=True),
                  "sts", "get-caller-identity")
    results.append(("key without session token", "denied", rc != 0, out))

    # 2. fabricated session token
    fake = dict(creds, session_token="F" * 300)
    rc, out = aws(env_for(doc, fake), "sts", "get-caller-identity")
    results.append(("key with fabricated token", "denied", rc != 0, out))

    # 3. the real thing
    rc, out = aws(env_for(doc, creds), "sts", "get-caller-identity")
    results.append(("key with captured token", "allowed", rc == 0, out))

    width = max(len(r[0]) for r in results)
    ok = True
    for label, expected, passed, detail in results:
        ok = ok and passed
        print("%-*s expected %-8s -> %s" % (width, label, expected,
                                            "PASS" if passed else "FAIL"))
        first = mask_text(detail).splitlines()
        print("    %s" % (first[0][:140] if first else ""))
        for line in first[1:4]:
            print("    %s" % line[:140])

    print("\n%s" % ("all three controls behaved as expected"
                    if ok else "a control did NOT behave as expected — investigate "
                                "before claiming the finding"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
