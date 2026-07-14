#!/usr/bin/env python3
"""Check that committed generated cPanel metadata matches its reviewed inputs."""

from __future__ import annotations

from generate_catalog import main

if __name__ == "__main__":
    raise SystemExit(main(["--check"]))
