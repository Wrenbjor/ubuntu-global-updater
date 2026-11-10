#!/bin/bash
# Forge recipe user: root. Pin a published/reviewed commit and its php85.sh hash.
set -Eeuo pipefail
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
UPDATER_COMMIT='REPLACE_WITH_REVIEWED_FULL_COMMIT_SHA'
UPDATER_SHA256='REPLACE_WITH_REVIEWED_PHP85_SH_SHA256'
UPDATER_MODE='--plan-only' # Change to --apply only for an authorized maintenance run.
[[ $EUID -eq 0 ]] || { echo 'FAILED: Select root as the Forge recipe user' >&2; exit 1; }
[[ $UPDATER_COMMIT =~ ^[0-9a-f]{40}$ && $UPDATER_SHA256 =~ ^[0-9a-f]{64}$ ]] || {
    echo 'FAILED: Set a published full commit SHA and reviewed php85.sh SHA256' >&2; exit 1;
}
[[ $UPDATER_MODE == --plan-only || $UPDATER_MODE == --apply || $UPDATER_MODE == --status ]] || exit 1
umask 077
work=$(mktemp -d)
trap 'rm -f -- "$work/php85.sh"; rmdir -- "$work"' EXIT
curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' \
    --connect-timeout 15 --max-time 120 --retry 2 \
    "https://raw.githubusercontent.com/Wrenbjor/ubuntu-global-updater/$UPDATER_COMMIT/php85.sh" \
    --output "$work/php85.sh"
printf '%s  %s\n' "$UPDATER_SHA256" "$work/php85.sh" | sha256sum --check --status
bash -n "$work/php85.sh"
echo "UPDATER START host=$(hostname) commit=$UPDATER_COMMIT mode=$UPDATER_MODE"
bash "$work/php85.sh" "$UPDATER_MODE"
if [[ $UPDATER_MODE == --apply ]]; then
    echo "UPDATER APPLY COMPLETED host=$(hostname)"
else
    echo "UPDATER $UPDATER_MODE COMPLETED: NO UPGRADE REQUESTED"
fi
