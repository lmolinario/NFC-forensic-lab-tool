import unittest

import proxmark3_backend as pm3


class Proxmark3BackendTests(unittest.TestCase):
    def test_allows_known_read_only_commands(self):
        commands = pm3.validate_read_only_commands([" HW VERSION ", "hf search"])
        self.assertEqual(commands, ["hw version", "hf search"])

    def test_rejects_write_command(self):
        with self.assertRaises(pm3.UnsafeCommandError):
            pm3.validate_read_only_commands(["hf mf wrbl --blk 1"])

    def test_rejects_unknown_command(self):
        with self.assertRaises(pm3.UnsafeCommandError):
            pm3.validate_read_only_commands(["hf unknown info"])

    def test_parses_common_identification_fields(self):
        transcript = """
        UID: 04 11 22 33 44 55 66
        ATQA: 00 44
        SAK: 00
        TYPE: NTAG213
        """
        parsed = pm3.parse_identification(transcript)
        self.assertEqual(parsed["uid"], "04 11 22 33 44 55 66")
        self.assertEqual(parsed["atqa"], "00 44")
        self.assertEqual(parsed["sak"], "00")
        self.assertEqual(parsed["technology_hint"], "NTAG / NFC Forum Type 2")


if __name__ == "__main__":
    unittest.main()
