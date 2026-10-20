# SPDX-License-Identifier: MIT
"""Public extraction contracts: independent reference digests and refusal paths."""
import copy
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import inputs
import prepare_seal
from pe import prepare_pe
from elf import extract_elf


class PublicInputs(unittest.TestCase):
    def test_public_manifest_admitted_without_private_reports(self):
        manifest, retained = inputs.validate_manifest(json.dumps(inputs.public_manifest()).encode())
        self.assertFalse(retained)
        self.assertEqual(manifest["physical_gpt"]["unique_guid"], "52444E41-494F-2044-7379-7374656D0000")

    def test_changed_contracts_are_rejected(self):
        changes = [
            ("physical_gpt", "unique_guid", "52444E41-494E-2044-7379-7374656D0000"),
            ("physical_gpt", "start_lba", 0),
            ("physical_gpt", "block_count", 1),
            ("seal", "chunk_bytes", 4096),
            ("seal", "chunk_count", 1),
            ("source_image", "sha256", "0" * 64),
            ("source_image", "bytes", 1),
        ]
        for section, field, value in changes:
            with self.subTest(section=section, field=field):
                manifest = copy.deepcopy(inputs.public_manifest())
                manifest[section][field] = value
                with self.assertRaises(ValueError):
                    inputs.validate_manifest(json.dumps(manifest).encode())

    def test_changed_file_or_artifact_identity_rejected(self):
        for field, key in [("files", "sources/boot.wim"), ("artifacts", "SystemVolumeSeal.h")]:
            manifest = copy.deepcopy(inputs.public_manifest())
            manifest[field][key]["sha256"] = "0" * 64
            with self.assertRaises(ValueError):
                inputs.validate_manifest(json.dumps(manifest).encode())

    def test_manifest_bound(self):
        with self.assertRaises(ValueError):
            inputs.validate_manifest(b" " * 65537)

    def test_generated_header_matches_independent_reference_digest(self):
        raw = prepare_seal.make_header(inputs.SYSTEM["seal"]["table_sha256"])
        self.assertEqual(len(raw), 1929)
        self.assertEqual(hashlib.sha256(raw).hexdigest(), "66a34f8bdf29262b092366f3a5b3d43e41aeb36d69f85acd5d2be920ba6426ec")

    def test_digest_size_and_symlink_refusal(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "test"
            path.write_bytes(b"test")
            entry = {"bytes": 4, "sha256": hashlib.sha256(b"test").hexdigest()}
            self.assertEqual(inputs.read_pinned(path, entry), b"test")
            with self.assertRaises(ValueError):
                inputs.read_pinned(path, dict(entry, bytes=3))
            with self.assertRaises(ValueError):
                inputs.read_pinned(path, dict(entry, sha256="0" * 64))
            link = Path(directory) / "link"
            link.symlink_to(path)
            with self.assertRaises(ValueError):
                inputs.read_pinned(link, entry)

    def test_preparer_rejects_wrong_image_before_output(self):
        with tempfile.TemporaryDirectory() as directory:
            image, output = Path(directory) / "image", Path(directory) / "out"
            image.write_bytes(b"not a supported image")
            with self.assertRaises(ValueError):
                prepare_seal.prepare(image, output)
            self.assertFalse(output.exists())

    def test_invalid_executable_headers_refused(self):
        for read in (prepare_pe, extract_elf):
            with self.subTest(reader=read.__name__):
                with self.assertRaises(ValueError):
                    read(bytes(64))


if __name__ == "__main__":
    unittest.main()
