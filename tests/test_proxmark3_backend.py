import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import proxmark3_backend as pm3


class Proxmark3BackendTests(unittest.TestCase):
    def test_safe_case_id(self):
        self.assertEqual(pm3.safe_case_id("CASE 2026/001"), "CASE_2026_001")

    def test_denied_command_is_rejected(self):
        with self.assertRaises(pm3.ProxmarkBackendError):
            pm3.validate_read_only_commands(["hf mf autopwn"])

    def test_parse_mifare_uid(self):
        parsed = pm3.parse_pm3_identification(
            "UID : B2 7B 50 17\nMIFARE Classic 1K\nISO 14443-A\n"
        )
        self.assertEqual(parsed["uid"], "B2 7B 50 17")
        self.assertIn("MIFARE Classic", parsed["families_detected"])
        self.assertIn("HF / NFC 13.56 MHz", parsed["technologies_detected"])

    def test_resolve_port_requires_explicit_choice_when_ambiguous(self):
        with patch.object(
            pm3,
            "discover_ports",
            return_value=[Path("/dev/ttyACM0"), Path("/dev/ttyACM1")],
        ):
            with self.assertRaises(pm3.ProxmarkBackendError):
                pm3.resolve_port()

    def test_write_hash_sidecar(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "evidence.log"
            path.write_text("evidence\n", encoding="utf-8")
            digest = pm3.write_hash_sidecar(path)
            sidecar = Path(f"{path}.sha256")
            self.assertTrue(sidecar.exists())
            self.assertIn(digest, sidecar.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
