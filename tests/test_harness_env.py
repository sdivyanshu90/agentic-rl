#!/usr/bin/env python3
"""Unit tests for rollout-environment isolation."""

import unittest
from unittest.mock import patch

from harness.env import ANSWER_DIR, REFERENCE_DIR, WORK_DIR, ContainerEnv


class ContainerEnvResetTest(unittest.TestCase):
    def test_reset_removes_and_recreates_all_mutable_agent_directories(self):
        env = ContainerEnv()
        calls = []

        with patch.object(env, "ensure_running") as ensure, patch.object(
            env, "restart"
        ) as restart, patch.object(
            env, "exec_root", side_effect=lambda args, **kw: calls.append(args)
        ):
            env.reset()

        ensure.assert_called_once_with()
        restart.assert_called_once_with()
        self.assertEqual(len(calls), 1)
        command = calls[0][-1]
        for path in (ANSWER_DIR, REFERENCE_DIR, WORK_DIR):
            self.assertIn(path, command)
        self.assertIn("rm -rf", command)
        self.assertIn("mkdir -p", command)


if __name__ == "__main__":
    unittest.main()
