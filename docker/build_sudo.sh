#!/bin/bash
#
# Deterministic sudo build helper for the CVE-2019-18634 lab.
# Usage: build_sudo.sh <version> <url> <sha256> <prefix>
#
set -euo pipefail

VERSION="$1"
URL="$2"
SHA256="$3"
PREFIX="$4"

mkdir -p /build
cd /build

TARBALL="sudo-${VERSION}.tar.gz"

echo "[*] Fetching sudo ${VERSION} from ${URL}"
curl -fsSL -o "${TARBALL}" "${URL}"

echo "[*] Verifying sha256"
echo "${SHA256}  ${TARBALL}" | sha256sum -c -

echo "[*] Extracting"
tar xzf "${TARBALL}"

cd "sudo-${VERSION}"

# Fixed configure flags so the resulting .bss layout (and therefore the
# exploit offsets) are deterministic for a given base image.
#
# NOTE on -fcommon:
#   GCC 10 changed the default from -fcommon to -fno-common.  On the distros
#   where CVE-2019-18634 was disclosed and exploited (e.g. Ubuntu 20.04 /
#   Debian 10, GCC 9) the tentative definitions of `tgetpass_flags` and
#   `user_details` were emitted as *common* symbols and the linker placed
#   them after tgetpass.o's .bss.  That ordering is what puts the privileged
#   globals after the vulnerable `buf` and makes the CVE exploitable.  We
#   reproduce that historical, vulnerable layout explicitly.
#
# NOTE on hardening:
#   We keep mainstream mitigations ON (PIE, FULL RELRO, stack protector, and
#   the kernel's NX + ASLR) so the exploit has to deal with them.
echo "[*] Configuring sudo ${VERSION} -> ${PREFIX}"
CFLAGS="-O2 -fcommon" ./configure \
    --prefix="${PREFIX}" \
    --sysconfdir=/etc \
    --without-pam \
    --disable-root-mailer \
    --disable-nls \
    --enable-hardening \
    --enable-pie \
    >/tmp/configure-"${VERSION}".log 2>&1

echo "[*] Building sudo ${VERSION}"
make -j"$(nproc)" >/tmp/make-"${VERSION}".log 2>&1

echo "[*] Installing sudo ${VERSION}"
make install >/tmp/install-"${VERSION}".log 2>&1

cd /build
rm -rf "sudo-${VERSION}" "${TARBALL}"

echo "[+] Built sudo ${VERSION} at ${PREFIX}"
