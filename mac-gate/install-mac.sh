#!/bin/bash
# Must be run locally by a Mac administrator, AFTER reviewing this code.
# Usage: sudo ./install-mac.sh /ABSOLUTE/PRIVATE/policy.json /ABSOLUTE/PRIVATE/secrets.json
set -euo pipefail
[[ "$(id -u)" == 0 ]] || { echo 'Run as root (sudo)' >&2; exit 1; }
[[ "$#" == 2 ]] || { echo 'Usage: sudo install-mac.sh /path/policy.json /path/secrets.json' >&2; exit 1; }
[[ -f "$1" && -f "$2" ]] || { echo 'Policy and secrets files must both exist' >&2; exit 1; }
/usr/bin/id vrchatprod >/dev/null 2>&1 || { echo 'Create standard Mac user vrchatprod first' >&2; exit 1; }
/usr/bin/dscl . -read /Groups/vrchatprod-auth >/dev/null 2>&1 || { echo 'Create dedicated group vrchatprod-auth first' >&2; exit 1; }
BASE='/opt/vrchat-prod'
SOURCE="$(cd "$(dirname "$0")" && pwd)"
# Use a root-controlled Python binary; a Homebrew binary owned by the
# untrusted Actions runner would permit an authorization bypass.
PYTHON3="${BROKER_PYTHON:-/usr/bin/python3}"
[[ -x "$PYTHON3" ]] || { echo 'Install root-owned Python3, then set BROKER_PYTHON to its absolute path' >&2; exit 1; }
REAL_PYTHON="$(/usr/bin/realpath "$PYTHON3")"
[[ "$(/usr/bin/stat -f %u "$REAL_PYTHON")" == 0 ]] || { echo 'Broker Python interpreter MUST be root-owned' >&2; exit 1; }
/usr/bin/install -d -o root -g wheel -m 755 "$BASE"
/usr/bin/install -o root -g wheel -m 755 "$SOURCE/broker.py" "$BASE/broker.py"
if [[ ! -d "$BASE/.venv" ]]; then
  "$PYTHON3" -m venv "$BASE/.venv"
fi
"$BASE/.venv/bin/python" -m pip install --disable-pip-version-check -r "$SOURCE/requirements.txt"
/usr/sbin/chown -R root:wheel "$BASE/.venv"
/usr/bin/install -o root -g vrchatprod-auth -m 640 "$1" "$BASE/policy.json"
/usr/bin/install -o root -g vrchatprod-auth -m 640 "$2" "$BASE/secrets.json"
/usr/bin/install -d -o vrchatprod -g vrchatprod-auth -m 700 "$BASE/receipts"
/usr/bin/touch "$BASE/deployment.lock"
/usr/sbin/chown vrchatprod:vrchatprod-auth "$BASE/deployment.lock"
/bin/chmod 600 "$BASE/deployment.lock"
# Config validation is offline and does not access GH or upload anything.
/usr/bin/sudo -n -u vrchatprod "$BASE/.venv/bin/python" "$BASE/broker.py" --check-config
cat <<'MESSAGE'
Broker installed. Next: configure a restrictive sudoers rule for ONLY the
broker (see SETUP-ja.md); create the vrchatprod SSH repo clone and VRCLI session.
DO NOT grant general sudo privileges to the Actions runner account.
MESSAGE
