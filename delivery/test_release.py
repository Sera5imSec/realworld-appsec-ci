import copy
import unittest
from build_release import trusted_ci


class ReleasePolicyTests(unittest.TestCase):
    def setUp(self):
        self.repository = "Sera5imSec/realworld-appsec-ci"
        self.revision = "a" * 40
        self.run = {"conclusion": "success", "status": "completed", "head_sha": self.revision,
                    "head_branch": "main", "event": "push", "path": ".github/workflows/ci.yml",
                    "head_repository": {"full_name": self.repository}}

    def test_successful_main_ci_is_accepted(self):
        self.assertTrue(trusted_ci(self.run, self.repository, self.revision))

    def test_failure_pr_other_commit_other_repository_and_schedule_are_rejected(self):
        changes = [{"conclusion": "failure"}, {"status": "in_progress"}, {"event": "pull_request"},
                   {"head_branch": "feature"}, {"head_sha": "b" * 40}, {"event": "schedule"},
                   {"path": ".github/workflows/matrix-sensitivity.yml"},
                   {"head_repository": {"full_name": "unrelated/fork"}}]
        for change in changes:
            with self.subTest(change=change):
                altered = copy.deepcopy(self.run)
                altered.update(change)
                self.assertFalse(trusted_ci(altered, self.repository, self.revision))


if __name__ == "__main__":
    unittest.main()
