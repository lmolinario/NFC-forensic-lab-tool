import argparse
import unittest

import proxmark3_active_lab as active


class Proxmark3ActiveLabTests(unittest.TestCase):
    def test_authorization_phrase_is_required(self):
        args = argparse.Namespace(
            authorization="wrong",
            timeout=45,
            expected_uid="B27B5017",
            operation="assess",
            page=None,
            block=None,
            key=None,
            key_type="A",
            password=None,
            expected_before=None,
            new_data=None,
        )
        with self.assertRaises(active.ActiveLabError):
            active.validate_arguments(args)

    def test_ntag_protected_pages_are_blocked(self):
        for page in (0, 1, 2, 3, 40, 41, 255):
            with self.subTest(page=page):
                with self.assertRaises(active.ActiveLabError):
                    active.validate_ntag_page(page)

    def test_ntag_user_page_is_allowed(self):
        active.validate_ntag_page(4)
        active.validate_ntag_page(39)

    def test_mfc_manufacturer_and_trailer_blocks_are_blocked(self):
        for block in (0, 3, 7, 11, 63):
            with self.subTest(block=block):
                with self.assertRaises(active.ActiveLabError):
                    active.validate_mfc_data_block(block)

    def test_mfc_data_blocks_are_allowed(self):
        for block in (1, 2, 4, 5, 6, 62):
            with self.subTest(block=block):
                active.validate_mfc_data_block(block)

    def test_contains_hex_accepts_spaced_output(self):
        output = "Block 04 | DE AD BE EF | ...."
        self.assertTrue(active.contains_hex(output, "DEADBEEF"))
        self.assertFalse(active.contains_hex(output, "00000000"))

    def test_secrets_are_redacted(self):
        command = "hf mf wrbl --blk 4 -k FFFFFFFFFFFF -d 00112233445566778899AABBCCDDEEFF"
        redacted = active.redact_text(command, ["FFFFFFFFFFFF"])
        self.assertNotIn("FFFFFFFFFFFF", redacted)
        self.assertIn("<REDACTED>", redacted)

    def test_command_builders(self):
        self.assertEqual(
            active.ntag_write_command(4, "DEADBEEF", None),
            "hf mfu wrbl -b 4 -d DEADBEEF",
        )
        self.assertEqual(
            active.mfc_write_command(4, "FFFFFFFFFFFF", "A", "00" * 16),
            "hf mf wrbl --blk 4 -a -k FFFFFFFFFFFF -d " + "00" * 16,
        )


if __name__ == "__main__":
    unittest.main()
