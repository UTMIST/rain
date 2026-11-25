import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, patch
from uuid import UUID

import rain as sync

ACTIVE = UUID("550e8400-e29b-41d4-a716-446655440000")
RETIRED = UUID("550e8400-e29b-41d4-a716-446655440001")
NAME = "msty-z3ucgb7g"

TEST_ED25519_KEY = (
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqq90UoX99a5Y5oWpQk2vXpQYkQ9i3O5mF9y5uW6pT test@example.com"
)
TEST_RSA_KEY = (
    "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC3r8p... user@example.com"
)


def roster(*rows):
    return json.dumps(rows).encode("utf-8")


class RosterTests(unittest.TestCase):
    def test_active_only_and_ignores_role_or_email(self):
        raw = roster(
            {"id": str(RETIRED), "active": False},
            {
                "id": str(ACTIVE),
                "active": True,
                "access_level": "superuser",
                "primary_email": "anything@example.org",
            },
        )
        self.assertEqual(sync.parse_roster(raw), [ACTIVE])
        self.assertEqual(sync.parse_roster(b"[]"), [])

    def test_rejects_whole_malformed_roster(self):
        valid = {"id": str(ACTIVE), "active": True}
        for body in (
            b"not JSON",
            b"{}",
            roster(valid, valid),
            roster({"id": str(ACTIVE)}),
            roster({"id": str(RETIRED), "active": "false"}),
            roster({"id": "bad id", "active": True}),
            roster({"id": str(UUID(int=0)), "active": True}),
        ):
            with self.subTest(body=body), self.assertRaises(sync.SyncError):
                sync.parse_roster(body)

    def test_username_is_a_stable_posix_name_and_is_short(self):
        self.assertEqual(sync.username(ACTIVE), NAME)
        self.assertRegex(NAME, r"^msty-[a-z2-7]{8}$")
        self.assertEqual(len(NAME), 13)
        self.assertNotEqual(sync.username(ACTIVE), sync.username(RETIRED))

    def test_username_related_to_person_name(self):
        cases = [
            ("Ada Lovelace", "msty-alovelace"),
            ("John Doe", "msty-jdoe"),
            ("Grace Brewster Murray Hopper", "msty-ghopper"),
            ("Jane", "msty-jane"),
            ("jean-luc picard", "msty-jpicard"),
            ("René Descartes", "msty-rdescartes"),
            ("ada.lovelace@mail.utoronto.ca", "msty-alovelace"),
            ("jdoe@utoronto.ca", "msty-jdoe"),
        ]
        for name_input, expected in cases:
            with self.subTest(name_input=name_input):
                self.assertEqual(sync.username(ACTIVE, name=name_input), expected)
                self.assertEqual(sync.username(name_input), expected)

    def test_roster_with_display_name_generates_name_based_username(self):
        raw = roster(
            {"id": str(ACTIVE), "display_name": "Ada Lovelace", "active": True}
        )
        people = sync.parse_roster(raw)
        self.assertEqual(len(people), 1)
        self.assertEqual(sync.username(people[0]), "msty-alovelace")

    def test_url_requires_https_and_no_userinfo_query_or_fragment(self):
        self.assertEqual(
            sync.staging_url("https://example.org/staging/"),
            "https://example.org/staging/people?active_only=true",
        )
        for value in (
            "http://example.org",
            "https://user@example.org",
            "https:///people",
            "https://example.org?prod=true",
            "https://example.org/#anything",
        ):
            with self.subTest(value=value), self.assertRaises(sync.SyncError):
                sync.staging_url(value)


class LocalUserProvisioningTests(unittest.TestCase):
    @patch.object(sync, "run")
    def test_add_local_user_uses_login_shell_and_home_dir(self, mock_run):
        sync.add_local_user("msty-testuser", ACTIVE)
        mock_run.assert_called_once_with(
            "/usr/sbin/useradd",
            "-m",
            "-U",
            "-l",
            "-d",
            "/home/msty-testuser",
            "-s",
            "/bin/bash",
            "-c",
            f"misty-staging={ACTIVE}",
            "-K",
            "UID_MIN=30000",
            "-K",
            "UID_MAX=39999",
            "-K",
            "GID_MIN=30000",
            "-K",
            "GID_MAX=39999",
            "--",
            "msty-testuser",
        )

    @patch("grp.getgrgid")
    @patch("pwd.getpwnam")
    def test_local_user_exists_checks(self, mock_getpwnam, mock_getgrgid):
        # Successful matching entry
        mock_entry = MagicMock()
        mock_entry.pw_uid = 30005
        mock_entry.pw_gid = 30005
        mock_entry.pw_gecos = f"misty-staging={ACTIVE}"
        mock_entry.pw_shell = "/bin/bash"
        mock_entry.pw_dir = "/home/msty-testuser"
        mock_getpwnam.return_value = mock_entry

        mock_grp = MagicMock()
        mock_grp.gr_name = "msty-testuser"
        mock_getgrgid.return_value = mock_grp

        self.assertTrue(sync.local_user_exists("msty-testuser", ACTIVE))

        # Rejects old nologin shell
        mock_entry.pw_shell = "/usr/sbin/nologin"
        with self.assertRaises(sync.SyncError):
            sync.local_user_exists("msty-testuser", ACTIVE)

        # Rejects non-existent home dir
        mock_entry.pw_shell = "/bin/bash"
        mock_entry.pw_dir = "/nonexistent"
        with self.assertRaises(sync.SyncError):
            sync.local_user_exists("msty-testuser", ACTIVE)


class SshKeyTests(unittest.TestCase):
    def test_validate_ssh_public_key_valid(self):
        valid, err, san, fp = sync.validate_ssh_public_key(TEST_ED25519_KEY)
        self.assertTrue(valid)
        self.assertEqual(err, "")
        self.assertIn("ssh-ed25519", san)
        self.assertTrue(fp.startswith("SHA256:"))

    def test_validate_ssh_public_key_rejects_private_key(self):
        priv = "-----BEGIN OPENSSH PRIVATE KEY-----\nbad\n-----END OPENSSH PRIVATE KEY-----"
        valid, err, _, _ = sync.validate_ssh_public_key(priv)
        self.assertFalse(valid)
        self.assertIn("Do not upload private keys", err)

    def test_validate_ssh_public_key_rejects_invalid_type(self):
        valid, err, _, _ = sync.validate_ssh_public_key("invalid-key-type AAAA test")
        self.assertFalse(valid)
        self.assertIn("Unsupported SSH key type", err)

    def test_save_and_install_ssh_key(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            keys_dir = Path(tmpdir) / "keys"
            home_dir = Path(tmpdir) / "home_msty"

            # Save key
            saved_path = sync.save_ssh_key(NAME, TEST_ED25519_KEY, keys_dir=str(keys_dir))
            self.assertTrue(saved_path.is_file())
            self.assertIn("ssh-ed25519", saved_path.read_text())

            # Install key
            home_dir.mkdir(parents=True, exist_ok=True)
            installed = sync.install_authorized_key(NAME, TEST_ED25519_KEY, home_dir=str(home_dir))
            self.assertTrue(installed)
            auth_file = home_dir / ".ssh" / "authorized_keys"
            self.assertTrue(auth_file.is_file())
            self.assertIn("ssh-ed25519", auth_file.read_text())

            # Check get_ssh_key_info
            info = sync.get_ssh_key_info(NAME, keys_dir=str(keys_dir))
            self.assertIsNotNone(info)
            self.assertTrue(info["fingerprint"].startswith("SHA256:"))


class ReconciliationTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        lock = patch.object(sync, "PROVISION_LOCK", Path(tmp.name) / "provision.lock")
        lock.start()
        self.addCleanup(lock.stop)
        passwd = patch.object(sync.pwd, "getpwall", return_value=[])
        self.passwd = passwd.start()
        self.addCleanup(passwd.stop)

    @patch.object(sync, "add_local_user")
    @patch.object(sync, "local_user_exists", return_value=False)
    @patch.object(sync, "run")
    def test_preview_then_creation_then_noop(self, run, exists, add_local):
        run.side_effect = ["|\n", "root|Administrator\n"]
        self.assertTrue(sync.reconcile([ACTIVE], "rain", "misty-staging", dry_run=True))
        add_local.assert_not_called()
        self.assertEqual(run.call_count, 2)

        run.reset_mock(side_effect=True)
        run.side_effect = ["|\n", "root|Administrator\n", ""]
        self.assertTrue(sync.reconcile([ACTIVE], "rain", "misty-staging"))
        add_local.assert_called_once_with(NAME, ACTIVE)
        run.assert_called_with(
            sync.SACCTMGR,
            "-i",
            "add",
            "user",
            NAME,
            "Cluster=rain",
            "Account=misty-staging",
        )

        run.reset_mock(side_effect=True)
        exists.return_value = True
        run.side_effect = [f"|\n{NAME}|\n", f"{NAME}|None\n"]
        self.assertTrue(sync.reconcile([ACTIVE], "rain", "misty-staging"))
        self.assertEqual(run.call_count, 2)
        add_local.assert_called_once()

    @patch.object(sync, "add_local_user")
    @patch.object(sync, "local_user_exists", return_value=True)
    @patch.object(sync, "run")
    def test_no_adoption_of_an_existing_admin(self, run, exists, add_local):
        run.side_effect = ["|\n", f"{NAME}|Administrator\n"]
        with self.assertLogs(sync.LOG, "ERROR"):
            self.assertFalse(sync.reconcile([ACTIVE], "rain", "misty-staging"))
        self.assertEqual(run.call_count, 2)
        add_local.assert_not_called()

    @patch.object(sync, "add_local_user")
    @patch.object(sync, "local_user_exists", return_value=True)
    @patch.object(sync, "run")
    def test_retries_slurm_only_if_posix_creation_already_succeeded(
        self, run, exists, add_local
    ):
        run.side_effect = ["|\n", "root|Administrator\n", ""]
        self.assertTrue(sync.reconcile([ACTIVE], "rain", "misty-staging"))
        self.assertEqual(run.call_count, 3)
        add_local.assert_not_called()

    @patch.object(sync, "run", return_value="")
    def test_requires_target_account_before_provisioning(self, run):
        with self.assertRaisesRegex(sync.SyncError, "not registered"):
            sync.reconcile([ACTIVE], "rain", "misty-staging")
        run.assert_called_once()

    @patch.object(sync, "local_user_exists", return_value=True)
    @patch.object(sync, "run")
    def test_keeps_existing_login_and_association_after_name_change(self, run, exists):
        login = "msty-existing"
        self.passwd.return_value = [SimpleNamespace(pw_name=login, pw_gecos=f"misty-staging={ACTIVE}")]
        run.side_effect = [f"|\n{login}|\n", f"{login}|None\n"]

        self.assertEqual(sync.provision_login(ACTIVE, "New Name", "rain", "misty-staging"), login)
        exists.assert_called_once_with(login, ACTIVE)
        self.assertEqual(run.call_count, 2)


if __name__ == "__main__":
    unittest.main()
