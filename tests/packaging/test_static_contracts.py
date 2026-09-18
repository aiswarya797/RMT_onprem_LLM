import hashlib
import os
import pathlib
import subprocess
import tempfile
import unittest
import xml.etree.ElementTree as ET


ROOT = pathlib.Path(__file__).resolve().parents[2]


class PackagingContractTests(unittest.TestCase):
    def test_distribution_is_current_user_only_and_apple_silicon(self):
        template = (ROOT / "packaging/macos/Distribution.xml.in").read_text()
        root = ET.fromstring(template.replace("@VERSION@", "0.1.0"))
        domains = root.find("domains")
        self.assertIsNotNone(domains)
        self.assertEqual(domains.attrib, {
            "enable_localSystem": "false",
            "enable_currentUserHome": "true",
            "enable_anywhere": "false",
        })
        options = root.find("options")
        self.assertEqual(options.attrib["hostArchitectures"], "arm64")
        self.assertEqual(root.find("allowed-os-versions/os-version").attrib["min"], "14.0")

    def test_release_mode_cannot_claim_trust_without_all_evidence(self):
        script = (ROOT / "packaging/macos/build.sh").read_text()
        for required in (
            "DEVELOPER_ID_APPLICATION is required for release mode",
            "DEVELOPER_ID_INSTALLER is required for release mode",
            "NOTARY_PROFILE is required for release mode",
            "CHECKSUM_SIGNING_KEY is required for release mode",
            'NOTARY_STATUS" = "Accepted',
            "stapler validate",
            "pkgutil --check-signature",
            "spctl --assess --type install",
            "openssl dgst -sha256 -verify",
        ):
            self.assertIn(required, script)
        self.assertLess(script.index('NOTARY_STATUS" = "Accepted'), script.index("qualified_release" if "qualified_release" in script else "write-release-manifest.mjs"))
        verifier = (ROOT / "packaging/macos/verify-release.sh").read_text()
        self.assertIn("EXPECTED_PUBLIC_KEY_SHA256", verifier)
        self.assertIn("EXPECTED_INSTALLER_IDENTITY", verifier)
        self.assertIn("supplied package does not match its signed checksum entry", verifier)
        self.assertNotIn("shasum -a 256 -c", verifier)

    def test_development_artifact_is_explicitly_unqualified(self):
        script = (ROOT / "packaging/macos/build.sh").read_text()
        self.assertIn("development-unsigned.pkg", script)
        self.assertIn("development-adhoc-darwin-arm64.tar.gz", script)
        self.assertIn("Development output is ad-hoc/unsigned, not notarized", script)
        self.assertIn("go1.26.8 darwin/arm64", script)
        self.assertIn("MACOSX_DEPLOYMENT_TARGET=14.0", script)
        self.assertIn('CGO_CFLAGS="-O2 -g -mmacosx-version-min=14.0"', script)
        self.assertIn('CGO_LDFLAGS="-mmacosx-version-min=14.0"', script)
        self.assertIn('vtool -show-build "$BIN_ROOT/$COMMAND"', script)
        self.assertIn("list -deps", script)
        self.assertNotIn("list -m", script)
        self.assertIn("package contains a path outside the current-user LLM Monitor root", script)
        self.assertIn("package is missing required payload", script)

    def test_sbom_includes_bundled_native_sqlite(self):
        generator = (ROOT / "packaging/scripts/write-sbom.mjs").read_text()
        self.assertIn('versionInfo: "3.53.4"', generator)
        self.assertIn("bf7c7f30031888f4e796e429ab3978879485813aaca6f641c7b33e4e09459bcc", generator)
        self.assertTrue((ROOT / "packaging/licenses/sqlite.txt").is_file())
        self.assertTrue((ROOT / "packaging/licenses/golang.org-x-sys.txt").is_file())

    def test_packaging_does_not_own_launchd_or_ollama_lifecycle(self):
        sources = "\n".join(
            path.read_text()
            for path in (ROOT / "packaging").rglob("*")
            if path.is_file()
        )
        forbidden = ("launchctl bootstrap", "launchctl bootout", "ollama pull", "ollama run", "caffeinate")
        for phrase in forbidden:
            self.assertNotIn(phrase, sources)

    def test_customer_commands_quote_paths_with_spaces_and_have_no_pipe_installer(self):
        install = (ROOT / "docs/install.md").read_text()
        self.assertIn('LLM_MONITOR="$HOME/Library/Application Support/LLM Monitor/bin/llm-monitor"', install)
        self.assertIn('installer -pkg "./LLM-Monitor-0.1.0.pkg" -target CurrentUserHomeDirectory', install)
        self.assertIn('uninstall --keep-data --deployment-generation "GENERATION-UUID"', install)
        self.assertIn('uninstall --purge --deployment-generation "GENERATION-UUID" --confirm-deployment "DEPLOYMENT-UUID" --backup-offer-acknowledged', install)
        self.assertIn("retry_arguments", install)
        self.assertIn("removal-receipt.json", install)
        self.assertIn("Do not run `setup local` between attempts", install)
        self.assertNotIn("curl |", install)
        self.assertNotIn("curl -s |", install)

    def test_offline_guides_are_script_free_and_self_contained(self):
        for page in (ROOT / "docs/offline").glob("*.html"):
            text = page.read_text()
            self.assertNotIn("<script", text.lower(), page.name)
            self.assertNotIn('href="http', text.lower(), page.name)
            self.assertIn("Content-Security-Policy", text, page.name)


class ReleaseVerifierFixtureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        work = ROOT / ".work/packaging-tests"
        work.mkdir(parents=True, exist_ok=True)
        cls.temp = tempfile.TemporaryDirectory(dir=work)
        cls.root = pathlib.Path(cls.temp.name)
        cls.release = cls.root / "release"
        cls.release.mkdir()
        cls.package = cls.release / "LLM-Monitor-0.1.0.pkg"
        cls.package.write_bytes(b"finite fake package fixture\n")
        package_digest = hashlib.sha256(cls.package.read_bytes()).hexdigest()
        archive_name = "LLM-Monitor-0.1.0-darwin-arm64.tar.gz"
        manifest_name = "LLM-Monitor-0.1.0-release-manifest.json"
        archive_digest = hashlib.sha256(b"alternative archive fixture\n").hexdigest()
        manifest_digest = hashlib.sha256(b'{"qualified_release":true}\n').hexdigest()
        cls.sums = cls.release / "LLM-Monitor-0.1.0-SHA256SUMS"
        cls.sums.write_text(
            f"{package_digest}  {cls.package.name}\n"
            f"{archive_digest}  {archive_name}\n"
            f"{manifest_digest}  {manifest_name}\n"
        )
        cls.archive = cls.release / archive_name
        cls.manifest = cls.release / manifest_name
        cls.key = cls.root / "fixture-key.pem"
        cls.public_key = cls.release / "LLM-Monitor-0.1.0-SHA256SUMS.pub.pem"
        cls.signature = cls.release / "LLM-Monitor-0.1.0-SHA256SUMS.sig"
        subprocess.run(["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", str(cls.key)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["openssl", "pkey", "-in", str(cls.key), "-pubout", "-out", str(cls.public_key)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["openssl", "dgst", "-sha256", "-sign", str(cls.key), "-out", str(cls.signature), str(cls.sums)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        cls.public_fingerprint = hashlib.sha256(cls.public_key.read_bytes()).hexdigest()
        cls.wrong_key = cls.root / "wrong-fixture-key.pem"
        cls.wrong_public_key = cls.root / "wrong-fixture-key.pub.pem"
        subprocess.run(["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", str(cls.wrong_key)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["openssl", "pkey", "-in", str(cls.wrong_key), "-pubout", "-out", str(cls.wrong_public_key)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        cls.identity = "Developer ID Installer: Fixture Corp (FIXTURE123)"
        cls.bin = cls.root / "bin"
        cls.bin.mkdir()
        cls._stub("pkgutil", f'#!/bin/sh\necho "Status: signed by a certificate trusted by macOS"\necho "1. {cls.identity}"\n')
        cls._stub("xcrun", "#!/bin/sh\nexit 0\n")
        cls._stub("spctl", "#!/bin/sh\nexit 0\n")
        cls._stub("installer", "#!/bin/sh\necho CurrentUserHomeDirectory\n")

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    @classmethod
    def _stub(cls, name, content):
        path = cls.bin / name
        path.write_text(content)
        path.chmod(0o755)

    def verify(self, package=None, sums=None, signature=None, public_key=None, fingerprint=None, identity=None):
        env = os.environ.copy()
        env["PATH"] = f"{self.bin}:{env['PATH']}"
        return subprocess.run([
            str(ROOT / "packaging/macos/verify-release.sh"),
            str(package or self.package),
            str(sums or self.sums),
            str(signature or self.signature),
            str(public_key or self.public_key),
            fingerprint or self.public_fingerprint,
            identity or self.identity,
        ], env=env, text=True, capture_output=True)

    def test_documented_four_file_set_passes_with_three_entry_signed_list(self):
        self.assertEqual(len(self.sums.read_text().splitlines()), 3)
        self.assertFalse(self.archive.exists())
        self.assertFalse(self.manifest.exists())
        result = self.verify()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_duplicate_selected_package_entry_is_rejected(self):
        duplicate_sums = self.root / "duplicate-SHA256SUMS"
        duplicate_sums.write_text(self.sums.read_text() + self.sums.read_text().splitlines()[0] + "\n")
        duplicate_signature = self.root / "duplicate-SHA256SUMS.sig"
        subprocess.run(
            ["openssl", "dgst", "-sha256", "-sign", str(self.key), "-out", str(duplicate_signature), str(duplicate_sums)],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        result = self.verify(sums=duplicate_sums, signature=duplicate_signature)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("duplicate package entries", result.stderr)

    def test_same_name_different_package_is_rejected(self):
        alternate_dir = self.root / "alternate"
        alternate_dir.mkdir(exist_ok=True)
        alternate = alternate_dir / self.package.name
        alternate.write_bytes(b"different package bytes\n")
        result = self.verify(package=alternate)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("does not match its signed checksum entry", result.stderr)

    def test_wrong_independently_published_key_fingerprint_is_rejected(self):
        result = self.verify(fingerprint="0" * 64)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("public key fingerprint does not match", result.stderr)

    def test_wrong_public_key_cannot_authenticate_the_checksum_list(self):
        wrong_fingerprint = hashlib.sha256(self.wrong_public_key.read_bytes()).hexdigest()
        result = self.verify(public_key=self.wrong_public_key, fingerprint=wrong_fingerprint)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Verification failure", result.stdout + result.stderr)

    def test_wrong_independently_published_identity_is_rejected(self):
        result = self.verify(identity="Developer ID Installer: Wrong Corp (WRONG12345)")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("installer identity does not match", result.stderr)

    def test_identity_must_match_the_leaf_installer_certificate_exactly(self):
        result = self.verify(identity="Developer ID Installer: Fixture Corp")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("installer identity does not match", result.stderr)


if __name__ == "__main__":
    unittest.main()
