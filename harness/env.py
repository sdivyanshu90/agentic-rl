"""
Container environment adapter for the CVE-2019-18634 rollout harness.

A "turn" is exactly one agent action and its observation: one shell command
executed as the unprivileged `player` user inside the container, plus the
combined stdout/stderr/exit-code returned.  The harness counts turns.
"""

import os
import subprocess
import time

ANSWER_DIR = "/home/player/answer"
REFERENCE_DIR = "/home/player/.ref"
WORK_DIR = "/home/player/work"


class ContainerDown(RuntimeError):
    pass


class ContainerEnv:
    def __init__(self, container="pwfeedback-lab", user="player", timeout=45):
        self.container = container
        self.user = user
        self.timeout = timeout

    def ensure_running(self):
        """Start the lab container if it is stopped; raise if it cannot run."""
        inspect = subprocess.run(
            ["docker", "inspect", "-f", "{{.State.Running}}", self.container],
            capture_output=True, text=True)
        if inspect.returncode != 0:
            raise ContainerDown("container %r not found: %s"
                                % (self.container, inspect.stderr.strip()))
        if inspect.stdout.strip() != "true":
            subprocess.run(["docker", "start", self.container],
                           capture_output=True, text=True)
            time.sleep(1.5)
            again = subprocess.run(
                ["docker", "inspect", "-f", "{{.State.Running}}", self.container],
                capture_output=True, text=True)
            if again.stdout.strip() != "true":
                raise ContainerDown("container %r could not be started" % self.container)

    def restart(self):
        """Restart the lab to discard processes left by timed-out execs."""
        restarted = subprocess.run(
            ["docker", "restart", "-t", "0", self.container],
            capture_output=True, text=True, timeout=30)
        if restarted.returncode != 0:
            raise ContainerDown("container %r could not be restarted: %s"
                                % (self.container, restarted.stderr.strip()))

    def _docker(self, args, user=None, workdir=None, timeout=None, input=None):
        cmd = ["docker", "exec"]
        if user:
            cmd += ["-u", user]
        if workdir:
            cmd += ["-w", workdir]
        if input is not None:
            cmd += ["-i"]
        cmd += [self.container] + args
        try:
            return subprocess.run(cmd, input=input, capture_output=True, text=True,
                                  timeout=timeout or self.timeout)
        except subprocess.TimeoutExpired as exc:
            # Killing the docker client does not necessarily kill its exec'd
            # process.  Restart the disposable lab so that a timed-out PTY or
            # sudo probe cannot keep running into later turns/rollouts.
            try:
                self.restart()
            except (ContainerDown, subprocess.TimeoutExpired):
                pass
            class _Timed:
                returncode = 124
                stdout = ""
                stderr = "command exceeded %ss and was killed" % (timeout or self.timeout)
            return _Timed()

    def exec_root(self, args, **kw):
        return self._docker(args, user=None, **kw)

    def exec_player(self, command, timeout=None):
        """Run one shell command as player.  Returns (output, exit_code)."""
        r = self._docker(["bash", "-lc", command], user=self.user,
                         workdir=ANSWER_DIR, timeout=timeout)
        out = (r.stdout or "") + (r.stderr or "")
        if "is not running" in out and "Error response from daemon" in out:
            raise ContainerDown("lab container stopped during a rollout")
        if len(out) > 8000:
            out = out[:8000] + "\n...[truncated]"
        return out, r.returncode

    def reset(self):
        """Wipe all mutable per-rollout state and recreate player work dirs."""
        self.ensure_running()
        self.restart()
        self.exec_root(["bash", "-lc",
                        "rm -rf %s %s %s && mkdir -p %s %s "
                        "&& chown -R %s:%s %s %s"
                        % (ANSWER_DIR, REFERENCE_DIR, WORK_DIR,
                           ANSWER_DIR, WORK_DIR, self.user, self.user,
                           ANSWER_DIR, WORK_DIR)])

    def stage_reference(self, local_dir):
        subprocess.run(["docker", "cp", local_dir + "/.",
                        "%s:%s" % (self.container, REFERENCE_DIR)],
                       capture_output=True, text=True, check=True)
        self.exec_root(["bash", "-lc",
                        "chown -R %s:%s %s && chmod +x %s/*.py %s/*.sh"
                        % (self.user, self.user, REFERENCE_DIR,
                           REFERENCE_DIR, REFERENCE_DIR)])

    def put_file(self, local_path, remote_path, mode="0644"):
        subprocess.run(["docker", "cp", local_path,
                        "%s:%s" % (self.container, remote_path)],
                       capture_output=True, text=True, check=True)
        self.exec_root(["chmod", mode, remote_path])
