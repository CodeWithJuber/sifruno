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
import stat

import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import web_runtime_fixture as fixture


class TraversalDenialChallenge(unittest.TestCase):
    def test_malformed_or_forbidden_or_missing_request_denial_is_accepted(self):
        for status in (400, 403, 404):
            with self.subTest(status=status):
                fixture.assert_traversal_denied(status, b"Rejected request")

    def test_success_redirect_and_server_failure_cannot_count_as_denial(self):
        for status in (200, 206, 301, 302, 307, 500, 502, 503, True, "400"):
            with self.subTest(status=status), self.assertRaises(fixture.FixtureError) as error:
                fixture.assert_traversal_denied(status, b"Rejected request")
            self.assertEqual(error.exception.code, "sibling_path_not_denied")

    def test_private_sentinel_leak_is_rejected_even_with_denial_status(self):
        for status in (400, 403, 404):
            with self.subTest(status=status), self.assertRaises(fixture.FixtureError):
                fixture.assert_traversal_denied(status, b"prefix SIFRUNO_PRIVATE_SENTINEL\n")


class WorkerIdentityChallenge(unittest.TestCase):
    status = ("Uid:\t20000 20000 20000 20000\nGid:\t20000 20000 20000 20000\nGroups:\t20000\n"
              "CapEff:\t0000000000000000\nCapPrm:\t0000000000000000\n"
              "CapAmb:\t0000000000000000\nCapInh:\t0000000000000000\n")
    root = "/srv/sifruno-web-jails/" + "a" * 32

    def test_all_ids_groups_and_no_capabilities_required(self):
        good = fixture.parse_proc_identity(self.status, self.root)
        self.assertTrue(fixture.worker_matches(good, 20000, 20000, self.root))
        for value in (
                self.status.replace("Uid:\t20000 20000", "Uid:\t20000 0"),
                self.status.replace("Gid:\t20000 20000", "Gid:\t20000 0"),
                self.status.replace("Groups:\t20000", "Groups:\t20000 0"),
                *[self.status.replace(f"{name}:\t0000000000000000", f"{name}:\t0000000000000001")
                  for name in ("CapEff", "CapPrm", "CapAmb", "CapInh")]):
            self.assertFalse(fixture.worker_matches(fixture.parse_proc_identity(value, self.root),
                                                   20000, 20000, self.root))
        self.assertFalse(fixture.worker_matches(good, 20000, 20000, "/"))

    def test_missing_duplicate_malformed_or_excessive_fields_rejected(self):
        for value in (self.status.replace("Groups:\t20000\n", ""), self.status + "Uid:\t1 1 1 1\n",
                      self.status.replace("20000 20000 20000 20000", "20000"),
                      self.status.replace("Groups:\t20000", "Groups:\t" + " ".join(str(x) for x in range(33))),
                      self.status + "x" * 8192):
            with self.subTest(value=value[:60]), self.assertRaises((KeyError, ValueError)):
                fixture.parse_proc_identity(value, self.root)

    def test_delayed_worker_is_polled_before_identity_admission(self):
        proc = SimpleNamespace(pid=77, poll=lambda: None)
        jail = Path(self.root)
        identity = fixture.parse_proc_identity(self.status, str(jail))
        with patch.object(fixture, "children", side_effect=[[], [88]]) as children, \
                patch.object(fixture, "process_identity", return_value=identity), \
                patch.object(fixture.time, "sleep"):
            fixture.assert_worker(proc, {"UID": 20000, "GID": 20000}, jail)
        self.assertEqual(children.call_count, 2)

    def test_dead_daemon_never_counts_as_ready(self):
        with self.assertRaises(fixture.FixtureError) as error:
            fixture.assert_worker(SimpleNamespace(pid=77, poll=lambda: 1),
                                  {"UID": 20000, "GID": 20000}, Path(self.root))
        self.assertEqual(error.exception.code, "owned_daemon_exited_before_workers")


class RuntimeReportChallenge(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name).resolve()
        self.path = self.root / "report.json"

    def tearDown(self):
        self.tmp.cleanup()

    def test_real_exclusive_report_is_utf8_json_with_original_failure(self):
        value = {"passed": False, "complete": True, "failure": "worker_not_observed", "note": "évidence"}
        fixture.write_runtime_report(self.path, self.root, value)
        data = self.path.read_bytes()
        self.assertEqual(json.loads(data), value)
        self.assertIn("évidence".encode("utf-8"), data)
        self.assertTrue(data.endswith(b"\n"))
        self.assertLessEqual(len(data), fixture.MAX_RUNTIME_REPORT)
        if os.name != "nt":
            self.assertEqual(stat.S_IMODE(self.path.stat().st_mode), 0o600)

    def test_existing_report_is_never_overwritten(self):
        original = b"prior admitted evidence\n"
        self.path.write_bytes(original)
        with self.assertRaises(fixture.FixtureError) as error:
            fixture.write_runtime_report(self.path, self.root, {"passed": True})
        self.assertEqual(error.exception.code, "report_path_not_exclusive")
        self.assertEqual(self.path.read_bytes(), original)

    def test_report_cannot_escape_admitted_parent(self):
        nested = self.root / "nested"
        nested.mkdir()
        with self.assertRaises(fixture.FixtureError) as error:
            fixture.write_runtime_report(nested / "report.json", self.root, {})
        self.assertEqual(error.exception.code, "report_path_not_exclusive")
        self.assertEqual(list(nested.iterdir()), [])

    def test_report_utf8_byte_bound_rejects_before_creating(self):
        with self.assertRaises(fixture.FixtureError) as error:
            fixture.write_runtime_report(self.path, self.root, {"note": "é" * (fixture.MAX_RUNTIME_REPORT // 2)})
        self.assertEqual(error.exception.code, "runtime_report_bound_exceeded")
        self.assertFalse(self.path.exists())

    def test_unserializable_report_does_not_create_empty_evidence(self):
        with self.assertRaises(TypeError):
            fixture.write_runtime_report(self.path, self.root, {"bad": object()})
        self.assertFalse(self.path.exists())

    def test_owned_log_tail_is_bounded_and_sanitized(self):
        path = self.root / "owned.log"
        path.write_bytes(b"Error: old prefix must not be read\n" + b"x" * 8192 +
                         b"\n\x1b[31mAH00072: could not bind\x1b[0m\x00\nError: password=never-print\n" +
                         b"Error: startup failed\n" * 10 + b"AH01084: pass request body failed\n")
        # Model the production log owner while using a real temporary file and
        # its actual link count, type and size on unprivileged CI runners.
        info = path.stat()
        owned = SimpleNamespace(st_mode=info.st_mode, st_nlink=info.st_nlink,
                                st_size=info.st_size, st_uid=0)
        with patch.object(fixture.os, "fstat", return_value=owned):
            lines = fixture.owned_log_diagnostics(path)
        with patch.object(fixture.os, "fstat", return_value=SimpleNamespace(
                st_mode=info.st_mode, st_nlink=info.st_nlink, st_size=info.st_size, st_uid=1001)):
            self.assertEqual(fixture.owned_log_diagnostics(path), [])
        self.assertIn("AH01084: pass request body failed", lines)
        self.assertEqual(len(lines), 4)
        self.assertTrue(all(len(line) <= 256 and all(c.isprintable() for c in line) for line in lines))
        self.assertNotIn("old prefix", " ".join(lines))
        self.assertNotIn("never-print", " ".join(lines))

    def test_hardlinked_log_is_not_admitted(self):
        path = self.root / "owned.log"
        path.write_bytes(b"Error: should not be admitted\n")
        os.link(path, self.root / "alias.log")
        self.assertEqual(fixture.owned_log_diagnostics(path), [])

    def test_apache_missing_module_continuation_is_retained_without_secrets(self):
        lines = fixture.diagnostic_lines(
            b"AH00526: Syntax error on line 5 of /var/lib/sifruno-web/apache/front.conf:\n"
            b"Invalid command 'Listen', perhaps misspelled or defined by a module not included in the server configuration\n"
            b"Invalid command 'password=never-print'\n")
        self.assertEqual(len(lines), 2)
        self.assertTrue(lines[1].startswith("Invalid command 'Listen'"))
        self.assertNotIn("never-print", " ".join(lines))

    def test_apache_mutex_continuations_are_bounded_and_retained(self):
        lines = fixture.diagnostic_lines(
            b"Mutex requires at least a mechanism and a list of mutex names\n"
            b"Invalid Mutex directory in argument file:/var/lib/sifruno-web/front-mutex\n"
            b"Mutex requires password=never-print\n")
        self.assertEqual(len(lines), 2)
        self.assertNotIn("never-print", " ".join(lines))


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

    def account_dtos(self):
        names = {"ID": "id", "Username": "username", "Domain": "domain", "Home": "home",
                 "PublicHTML": "public_html", "State": "state", "UID": "uid", "GID": "gid",
                 "Revision": "revision", "CreatedAt": "created_at", "UpdatedAt": "updated_at"}
        return [{names[key]: value for key, value in account.items()} for account in self.accounts]

    def test_actual_dto_envelope_metadata_stripped_and_states_retained(self):
        items = self.account_dtos()
        items[1]["state"] = "suspended"
        path = Path(self.tmp.name) / "accounts.json"
        for metadata in ({}, {"$schema": "http://127.0.0.1:18080/AccountListBody.json"}):
            with self.subTest(metadata=metadata):
                envelope = {"items": items, **metadata}
                path.write_text(json.dumps(envelope), encoding="utf-8")
                normalized = fixture.account_items(json.loads(path.read_bytes()))
                self.assertEqual(normalized, items)
                self.assertEqual(set(normalized[0]), set(items[0]))
                validated = fixture.accounts_from(path, self.profile, allow_suspended=True)
                self.assertEqual([account["State"] for account in validated], ["active", "suspended"])
                self.assertEqual([account["ID"] for account in validated], [account["id"] for account in items])
                with self.assertRaises(fixture.FixtureError) as error:
                    fixture.accounts_from(path, self.profile)
                self.assertEqual(error.exception.code, "account_schema_invalid")

    def test_invalid_schema_metadata_rejected(self):
        invalid = (None, {}, [], 42, "", "x" * 2049, "http://example.test/AccountListBody.json\n",
                   "http://example.test/AccountListBody.json\x00", "http://é.test/AccountListBody.json",
                   "not-a-url", "file:///AccountListBody.json", "http://secret@example.test/AccountListBody.json",
                   "http://example.test/Other.json", "http://example.test/AccountListBody.json?fetch=1")
        for metadata in invalid:
            with self.subTest(metadata=metadata):
                with self.assertRaises(fixture.FixtureError) as error:
                    fixture.account_items({"items": self.account_dtos(), "$schema": metadata})
                self.assertEqual(error.exception.code, "account_list_metadata_invalid")

    def test_unknown_envelope_fields_and_account_bounds_remain_rejected(self):
        items = self.account_dtos()
        for value in ({"items": items, "extra": True}, {"items": items, "$Schema": "ignored"},
                      {"$schema": "http://example.test/AccountListBody.json"}, items):
            with self.subTest(value=value):
                with self.assertRaises(fixture.FixtureError) as error:
                    fixture.account_items(value)
                self.assertEqual(error.exception.code, "account_list_schema_invalid")
        for value in ([], items + [items[0]], "not-an-array"):
            with self.assertRaises(fixture.FixtureError) as error:
                fixture.account_items({"items": value})
            self.assertEqual(error.exception.code, "account_count_invalid")

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
            for name, ip, domain in (("wrong", "127.73.255.254", "wrong-backend.example.invalid"),
                                     ("good", cls.ip, cls.account["Domain"]),
                                     ("wrong_own_dns", "127.73.255.254", cls.account["Domain"])):
                extension = cls.root / f"{name}.ext"
                extension.write_text(f"basicConstraints=critical,CA:false\nkeyUsage=critical,digitalSignature,keyEncipherment\nsubjectAltName=DNS:{domain},IP:{ip}\n", encoding="ascii")
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

    def test_wrong_ip_with_original_domain_cannot_count_as_wrong_peer_name(self):
        with self.assertRaises(fixture.FixtureError) as error:
            self.inspect(serving="wrong_own_dns", expected="wrong_own_dns")
        self.assertEqual(error.exception.code, "wrong_backend_presented_san_invalid")

    def test_good_leaf_has_real_strict_domain_and_ip_tls_verification(self):
        server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server_context.load_cert_chain(self.root / "good.pem", self.root / "good.key")
        listener = socket.socket()
        listener.settimeout(5)
        listener.bind((self.ip, 0))
        listener.listen(2)
        failures = []

        def serve():
            try:
                for _ in range(2):
                    with listener.accept()[0] as raw:
                        raw.settimeout(3)
                        with server_context.wrap_socket(raw, server_side=True) as conn:
                            conn.recv(4096)
                            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
            except (OSError, ssl.SSLError) as error:
                failures.append(type(error).__name__)

        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        client_context = ssl.create_default_context(cafile=str(self.root / "ca.pem"))
        self.assertTrue(client_context.check_hostname)
        self.assertEqual(client_context.verify_mode, ssl.CERT_REQUIRED)
        try:
            for name in (self.account["Domain"], self.ip):
                with socket.create_connection(listener.getsockname(), timeout=3) as raw:
                    with client_context.wrap_socket(raw, server_hostname=name) as conn:
                        self.assertIn(("DNS", self.account["Domain"]), conn.getpeercert()["subjectAltName"])
                        self.assertIn(("IP Address", self.ip), conn.getpeercert()["subjectAltName"])
                        conn.sendall(b"GET / HTTP/1.1\r\nHost: webalpha.example.test\r\nConnection: close\r\n\r\n")
                        response = fixture.http.client.HTTPResponse(conn)
                        response.begin()
                        self.assertEqual(response.status, 200)
                        self.assertEqual(response.read(3), b"ok")
        finally:
            listener.close()
            thread.join(timeout=6)
        self.assertFalse(thread.is_alive())
        self.assertEqual(failures, [])

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
