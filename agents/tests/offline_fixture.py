"""Shared setup for the offline tests: use the fixture topology (tests/range.test.yaml) instead of your range.yaml.

Call use_fixture() BEFORE importing anything from airange - topology.py reads AIRANGE_RANGE_FILE at import time.
"""
import os
import sys
from pathlib import Path

FIXTURE = Path(__file__).resolve().with_name("range.test.yaml")
# Env overrides of values that otherwise come from the topology (see airange/config.py)
_OVERRIDES = ("AIRANGE_KALI_HOST", "AIRANGE_TARGET_CIDR", "AIRANGE_TARGET_EXCLUDE", "AIRANGE_MGMT_IPS",
              "AIRANGE_DOMAIN")


def use_fixture() -> None:
    if "airange.topology" in sys.modules:
        raise RuntimeError("use_fixture() must run before airange is imported")
    os.environ["AIRANGE_RANGE_FILE"] = str(FIXTURE)
    for name in _OVERRIDES:
        os.environ.pop(name, None)
