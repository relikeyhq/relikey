# SPDX-License-Identifier: EUPL-1.2
"""The edge installer's side of enrolment by code, as fleet_test.go drives it: deploy/edge/install.py's own
enrol_by_code, with the code from a file and the edge's enrolment seed from a file.

    python installer_enrol.py <deploy/edge/install.py> <code file> <seed file>
"""
import importlib.util
import sys
from pathlib import Path

spec = importlib.util.spec_from_file_location("edge_install", sys.argv[1])
install = importlib.util.module_from_spec(spec)
spec.loader.exec_module(install)
install.enrol_by_code(sys.argv[2], bytes.fromhex(Path(sys.argv[3]).read_text().strip()))
