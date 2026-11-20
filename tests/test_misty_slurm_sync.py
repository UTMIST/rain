import json
import unittest
from unittest.mock import patch
from uuid import UUID

import rain as sync

ACTIVE = UUID("550e8400-e29b-41d4-a716-446655440000")
RETIRED = UUID("550e8400-e29b-41d4-a716-446655440001")
NAME = "msty-kuhiiahctna5jjywirtfkraaaa"


def roster(*rows):
    return json.dumps(rows).encode("utf-8")


class RosterTests(unittest.TestCase):
    def test_active_only_and_ignores_role_or_email(self):
        raw = roster(
            {"id": str(RETIRED), "active": False},
            {"id": str(ACTIVE), "active": True, "access_level": "superuser",
             "primary_email": "anything@example.org"},
        )
        self.assertEqual(sync.parse_roster(raw), [ACTIVE])
        self.assertEqual(sync.parse_roster(b"[]"), [])

    def test_rejects_whole_malformed_roster(self):
        valid = {"id": str(ACTIVE), "active": True}
        for body in (
            b"not JSON", b"{}", roster(valid, valid), roster({"id": str(ACTIVE)}),
            roster({"id": str(RETIRED), "active": "false"}),
            roster({"id": "bad id", "active": True}),
            roster({"id": str(UUID(int=0)), "active": True}),
        ):
            with self.subTest(body=body), self.assertRaises(sync.SyncError):
                sync.parse_roster(body)

    def test_username_is_a_stable_posix_name_and_uses_full_uuid(self):
        self.assertEqual(sync.username(ACTIVE), NAME)
        self.assertRegex(NAME, r"^msty-[a-z2-7]{26}$")
        self.assertNotEqual(sync.username(ACTIVE), sync.username(RETIRED))

    def test_url_requires_https_and_no_userinfo_query_or_fragment(self):
        self.assertEqual(sync.staging_url("https://example.org/staging/"),
                         "https://example.org/staging/people?active_only=true")
        for value in ("http://example.org", "https://user@example.org", "https:///people",
                      "https://example.org?prod=true", "https://example.org/#anything"):
            with self.subTest(value=value), self.assertRaises(sync.SyncError):
                sync.staging_url(value)


class ReconciliationTests(unittest.TestCase):
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
        run.assert_called_with(sync.SACCTMGR, "-i", "add", "user", NAME,
                               "Cluster=rain", "Account=misty-staging")

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
    def test_retries_slurm_only_if_posix_creation_already_succeeded(self, run, exists, add_local):
        run.side_effect = ["|\n", "root|Administrator\n", ""]
        self.assertTrue(sync.reconcile([ACTIVE], "rain", "misty-staging"))
        self.assertEqual(run.call_count, 3)
        add_local.assert_not_called()

    @patch.object(sync, "run", return_value="")
    def test_requires_target_account_before_provisioning(self, run):
        with self.assertRaisesRegex(sync.SyncError, "not registered"):
            sync.reconcile([ACTIVE], "rain", "misty-staging")
        run.assert_called_once()


if __name__ == "__main__":
    unittest.main()
