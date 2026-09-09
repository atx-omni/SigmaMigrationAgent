"""Isolation for all lab tests, including independently authored formula probes."""
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT.parents[1] / "packages/omnikit-migration-engine/src"))

import pytest
from preflight import NetworkDeny


@pytest.fixture(autouse=True)
def prohibit_real_network_for_every_test():
    with NetworkDeny():
        yield
