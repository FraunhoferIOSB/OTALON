#!/usr/bin/env python3
"""Initialize an empty continuous-data volume without repairing existing data.

Run in a one-off container against exactly the intended named volume. This helper
never traverses children or changes a populated volume's owner or mode.
"""

from __future__ import annotations

import argparse
import os
import stat
from pathlib import Path


def prepare(root, uid):
    root = Path(root).absolute()
    if not isinstance(uid, int) or uid < 0:
        raise ValueError("invalid owner")
    for part in [root, *root.parents]:
        if part.is_symlink():
            raise ValueError("symlink volume refused")
    info = root.stat()
    if not stat.S_ISDIR(info.st_mode):
        raise ValueError("volume must be a directory")
    expected = (uid, uid, 0o700)
    current = (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode))
    if current == expected:
        return
    populated = any(root.iterdir())
    if populated:
        if current != expected:
            raise ValueError("existing volume metadata mismatch; no automatic repair")
        return
    if current != expected:
        if (info.st_uid, info.st_gid) != (uid, uid):
            os.chown(root, uid, uid)
        os.chmod(root, 0o700)
    after = root.stat()
    if (after.st_uid, after.st_gid, stat.S_IMODE(after.st_mode)) != expected:
        raise ValueError("volume metadata verification failed")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True)
    parser.add_argument("--uid", required=True, type=int)
    args = parser.parse_args()
    try:
        prepare(args.root, args.uid)
    except (ValueError, OSError):
        print("Continuous volume preparation refused; inspect exact volume metadata. No recursive repair.")
        return 1
    print("Continuous volume ready; existing data preserved.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
