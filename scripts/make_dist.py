#!/usr/bin/env python3
"""Build a submission zip (source, environment, solutions, rubric, docs)."""

import hashlib
import os
import sys
import zipfile

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
VERSION = sys.argv[1] if len(sys.argv) > 1 else "1.0.0"
OUT_DIR = os.path.join(REPO, "dist")
NAME = "agentic-rl-sudo-pwfeedback-%s.zip" % VERSION
OUT = os.path.join(OUT_DIR, NAME)

EXCLUDE_DIRS = {".git", "dist", "__pycache__", "artifacts"}
EXCLUDE_FILES = {".env"}
EXCLUDE_EXT = {".pyc"}


def main():
    os.makedirs(OUT_DIR, exist_ok=True)
    with zipfile.ZipFile(OUT, "w", zipfile.ZIP_DEFLATED) as zf:
        for root, dirs, files in os.walk(REPO):
            dirs[:] = [d for d in dirs if d not in EXCLUDE_DIRS]
            for f in files:
                if f in EXCLUDE_FILES or os.path.splitext(f)[1] in EXCLUDE_EXT:
                    continue
                full = os.path.join(root, f)
                rel = os.path.relpath(full, REPO)
                zf.write(full, rel)
    digest = hashlib.sha256(open(OUT, "rb").read()).hexdigest()
    with open(os.path.join(OUT_DIR, "SHA256SUMS"), "w") as fh:
        fh.write("%s  %s\n" % (digest, NAME))
    print("%s  %s" % (digest, OUT))


if __name__ == "__main__":
    main()
