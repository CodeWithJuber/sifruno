import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch
import os
import shutil
import socket
import ssl
import subprocess
import threading

import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import web_runtime_fixture as fixture


class HostwebFixtureChallenge(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.profile = {
            "Name": "restricted-chroot-v1", "ManagedRoot": "/var/lib/sifruno/hostweb",
            "ManagedHomeRoot": "/srv/sifruno-managed-homes", "FrontChroot": "/var/lib/sifruno/front-jail",
            "ApacheModuleRoot": "/usr/lib64/httpd/modules", "BackendChrootRoot": "/var/lib/sifruno/backend-jails",
            "RuntimeRoot": "/run/sifruno/hostweb", "ApacheBinary": "/usr/sbin/httpd", "FPMBinary": "/usr/sbin/php-fpm",
            "TLSRoot": "/etc/sifruno/tls", "CAFile": "/etc/sifruno/tls/ca.pem", "FrontendIP": "127.0.0.1",
            "FrontendPort": 18444, "BackendPort": 18443, "FrontUID": 48, "FrontGID": 48, "ControllerUID": 2000,
        }
        self.accounts = []
        for index, name in enumerate(("webalpha", "webbravo")):
            uid = 20000 + index
            home = "/srv/sifruno-managed-homes/" + name
            self.accounts.append({"ID": ("a" if index == 0 else "b") * 32, "Username": name,
                "Domain": name + ".example.test", "Home": home, "PublicHTML": home + "/public_html",
                "State": "active", "UID": uid, "GID": uid, "Revision": 1,
                "CreatedAt": "2026-10-05T00:00:00Z", "UpdatedAt": "2026-10-05T00:00:00Z"})

    def tearDown(self):
        self.tmp.cleanup()

    def write_profile(self, value=None):
        path = Path(self.tmp.name) / "profile.json"
        path.write_text(json.dumps(value or self.profile), encoding="utf-8")
        return path

    def make_bundle(self, front_override=None, bare_session=False):
        p, a, b = self.profile, self.accounts[0], self.accounts[1]
        front = "\n".join(["ProxyPreserveHost On", "User #48", "Group #48", "SSLProxyVerify require",
            "SSLProxyCheckPeerName on", "SSLProxyCheckPeerExpire on", f'SSLProxyCACertificateFile "{p["CAFile"]}"',
            f"ProxyPass / https://127.73.{a['UID'] >> 8}.{a['UID'] & 255}:18443/",
            f"ProxyPass / https://127.73.{b['UID'] >> 8}.{b['UID'] & 255}:18443/"]) + "\n"
        files = {"apache/front.conf": (front if front_override is None else front_override).encode()}
        for account in self.accounts:
            aid, uid = account["ID"], account["UID"]
            files[f"apache/backends/{aid}.conf"] = (f'ChrootDir "{p["BackendChrootRoot"]}/{aid}"\n'
                f"User #{uid}\nGroup #{uid}\nListen 127.73.{uid >> 8}.{uid & 255}:18443\n"
                f'DocumentRoot "{account["PublicHTML"]}"\n{p["RuntimeRoot"]}/{aid}/php-fpm.sock\n').encode()
            session = "session.save_path" if bare_session else "php_admin_value[session.save_path]"
            files[f"fpm/{aid}.conf"] = (f"user = {uid}\ngroup = {uid}\nchroot = {p['BackendChrootRoot']}/{aid}\n"
                f"listen = {p['RuntimeRoot']}/{aid}/php-fpm.sock\n{session} = {account['Home']}/tmp\n").encode()
        records, digest = [], hashlib.sha256()
        for name in sorted(files):
            data, h = files[name], hashlib.sha256(files[name]).hexdigest()
            records.append({"path": name, "mode": "0600", "sha256": h, "config": data.decode()})
            digest.update(name.encode() + b"\0" + b"600\0" + h.encode() + b"\0")
        value = {"schemaVersion": 1, "compatibility": False, "activation": False,
                 "bundle": {"profile": p["Name"], "files": records, "sha256": digest.hexdigest()}}
        path = Path(self.tmp.name) / "bundle.json"
        path.write_text(json.dumps(value), encoding="utf-8")
        return path

    def test_valid_exact_bundle_admits(self):
        profile = fixture.profile_from(self.write_profile())
        bundle, files = fixture.bundle_from(self.make_bundle(), profile, self.accounts)
        self.assertEqual(bundle["profile"], "restricted-chroot-v1")
        self.assertEqual(len(files), 5)

    def test_rejects_bare_session_save_path_pool_directive(self):
        profile = fixture.profile_from(self.write_profile())
        with self.assertRaises(fixture.FixtureError) as error:
            fixture.bundle_from(self.make_bundle(bare_session=True), profile, self.accounts)
        self.assertEqual(error.exception.code, "tenant_runtime_directive_missing")

    def test_rejects_client_dns_host_gate(self):
        profile = fixture.profile_from(self.write_profile())
        with self.assertRaises(fixture.FixtureError) as error:
            fixture.bundle_from(self.make_bundle("Require host webalpha.example.test\n"), profile, self.accounts)
        self.assertEqual(error.exception.code, "front_tls_or_host_gate_missing")

    def test_rejects_bundle_digest_tamper(self):
        profile = fixture.profile_from(self.write_profile())
        path = self.make_bundle(); value = json.loads(path.read_text())
        value["bundle"]["files"][0]["config"] = "tampered"; path.write_text(json.dumps(value))
        with self.assertRaises(fixture.FixtureError) as error:
            fixture.bundle_from(path, profile, self.accounts)
        self.assertEqual(error.exception.code, "bundle_file_hash_invalid")

    def test_rejects_unsafe_profile_token(self):
        value = dict(self.profile); value["CAFile"] = '/etc/sifruno/tls/ca".pem'
        with self.assertRaises(fixture.FixtureError) as error:
            fixture.profile_from(self.write_profile(value))
        self.assertEqual(error.exception.code, "unsafe_posix_path")

    def test_rejects_front_without_proxy_tls_contract(self):
        profile = fixture.profile_from(self.write_profile())
        with self.assertRaises(fixture.FixtureError) as error:
            fixture.bundle_from(self.make_bundle("ProxyPass / https://127.73.78.32:18443/\n"), profile, self.accounts)
        self.assertEqual(error.exception.code, "front_tls_or_host_gate_missing")


class WrongCertificateInspection(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        openssl = shutil.which("openssl")
        if openssl is None and os.name == "nt":
            candidate = Path("C:/Program Files/Git/usr/bin/openssl.exe")
            openssl = str(candidate) if candidate.is_file() else None
        if openssl is None:
            raise unittest.SkipTest("OpenSSL unavailable for real local TLS regression")
        cls.tmp = tempfile.TemporaryDirectory()
        cls.root = Path(cls.tmp.name)
        cls.account = {"UID": 20000, "Username": "webalpha", "Domain": "webalpha.example.test"}
        cls.ip = "127.73.78.32"
        config = cls.root / "openssl.cnf"
        config.write_text("[req]\nprompt=no\ndistinguished_name=dn\nx509_extensions=ca\n[dn]\nCN=Disposable fixture CA\n[ca]\nbasicConstraints=critical,CA:true\nkeyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\n", encoding="ascii")

        def command(*args):
            result = subprocess.run([openssl, *args], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20,
                                    creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0)
            if result.returncode != 0:
                raise RuntimeError("isolated TLS fixture generation failed")

        try:
            command("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-config", str(config),
                    "-keyout", str(cls.root / "ca.key"), "-out", str(cls.root / "ca.pem"))
            for name, ip in (("wrong", "127.73.255.254"), ("good", cls.ip)):
                extension = cls.root / f"{name}.ext"
                extension.write_text(f"basicConstraints=critical,CA:false\nkeyUsage=critical,digitalSignature,keyEncipherment\nsubjectAltName=IP:{ip}\n", encoding="ascii")
                command("req", "-new", "-newkey", "rsa:2048", "-nodes", "-config", str(config), "-subj", f"/CN={ip}",
                        "-keyout", str(cls.root / f"{name}.key"), "-out", str(cls.root / f"{name}.csr"))
                command("x509", "-req", "-days", "1", "-in", str(cls.root / f"{name}.csr"), "-CA", str(cls.root / "ca.pem"),
                        "-CAkey", str(cls.root / "ca.key"), "-CAcreateserial", "-extfile", str(extension), "-out", str(cls.root / f"{name}.pem"))
            command("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-config", str(config),
                    "-keyout", str(cls.root / "untrusted.key"), "-out", str(cls.root / "untrusted.pem"))
        except Exception:
            cls.tmp.cleanup()
            raise

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def inspect(self, serving="wrong", expected="wrong", body=b"SIFRUNO_STATIC_webalpha\n"):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(self.root / f"{serving}.pem", self.root / f"{serving}.key")
        listener = socket.socket()
        listener.settimeout(5)
        listener.bind((self.ip, 0))
        listener.listen(1)
        profile = {"BackendPort": listener.getsockname()[1]}
        requests = []

        def serve():
            try:
                with listener.accept()[0] as raw:
                    with context.wrap_socket(raw, server_side=True) as conn:
                        request = conn.recv(4096)
                        requests.append(request)
                        conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: " + str(len(body)).encode() + b"\r\nConnection: close\r\n\r\n" + body)
            except (OSError, ssl.SSLError):
                pass  # Rejection clients deliberately close without an HTTP request.

        worker = threading.Thread(target=serve, daemon=True)
        worker.start()
        real_context = ssl.create_default_context
        contexts = []

        def client_context(**kwargs):
            result = real_context(**kwargs)
            contexts.append(result)
            return result

        try:
            # Only filesystem ownership is substituted on non-root test hosts;
            # certificate, CA chain, socket, request and body are real.
            with patch.object(fixture, "verify_root_file", side_effect=fixture.sha256), \
                    patch.object(fixture.ssl, "create_default_context", side_effect=client_context):
                fixture.inspect_wrong_backend_certificate(SimpleNamespace(poll=lambda: None), self.account,
                    profile, self.root / "ca.pem", self.root / f"{expected}.pem", "127.73.255.254")
            self.assertEqual(contexts[0].verify_mode, ssl.CERT_REQUIRED)
            self.assertFalse(contexts[0].check_hostname)
            self.assertIn(b"Host: webalpha.example.test\r\n", requests[0])
        finally:
            listener.close()
            worker.join(timeout=6)
            self.assertFalse(worker.is_alive())

    def test_live_wrong_san_leaf_and_exact_account_body_admit_inspection(self):
        self.inspect()

    def test_wrong_presented_leaf_rejected(self):
        with self.assertRaises(fixture.FixtureError) as error:
            self.inspect(serving="good", expected="wrong")
        self.assertEqual(error.exception.code, "wrong_backend_presented_certificate_mismatch")

    def test_expected_leaf_with_correct_san_cannot_count_as_wrong_san(self):
        with self.assertRaises(fixture.FixtureError) as error:
            self.inspect(serving="good", expected="good")
        self.assertEqual(error.exception.code, "wrong_backend_presented_san_invalid")

    def test_untrusted_chain_rejected_even_with_hostname_inspection_disabled(self):
        with self.assertRaises(fixture.FixtureError) as error:
            self.inspect(serving="untrusted", expected="untrusted")
        self.assertEqual(error.exception.code, "wrong_backend_inspection_chain_invalid")

    def test_wrong_account_body_rejected(self):
        with self.assertRaises(fixture.FixtureError) as error:
            self.inspect(body=b"SIFRUNO_STATIC_webbravo\n")
        self.assertEqual(error.exception.code, "wrong_backend_static_probe_invalid")

    def test_dead_backend_rejected_before_any_connection(self):
        with patch.object(fixture, "verify_root_file", side_effect=fixture.sha256), \
                patch.object(fixture.socket, "create_connection") as connect:
            with self.assertRaises(fixture.FixtureError) as error:
                fixture.inspect_wrong_backend_certificate(SimpleNamespace(poll=lambda: 1), self.account,
                    {"BackendPort": 18443}, self.root / "ca.pem", self.root / "wrong.pem", "127.73.255.254")
        self.assertEqual(error.exception.code, "wrong_backend_process_exited")
        connect.assert_not_called()

    def test_owned_startup_stderr_read_is_bounded(self):
        proc = SimpleNamespace(stderr=SimpleNamespace(fileno=lambda: 42))
        with patch.object(fixture.os, "set_blocking") as blocking, \
                patch.object(fixture.os, "read", return_value=b"Error: startup failed\n" * 30) as read:
            lines = fixture.replacement_startup_diagnostics(proc)
        blocking.assert_called_once_with(42, False)
        read.assert_called_once_with(42, 4096)
        self.assertEqual(len(lines), 4)
        self.assertTrue(all(len(line) <= 256 for line in lines))


if __name__ == "__main__":
    unittest.main()
