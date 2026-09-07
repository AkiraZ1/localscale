#!/bin/sh
# Validate LocalScale Onion deployment metadata without touching Tor or key files.
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
TEMPLATES="$ROOT/templates"
mode=""
env_file=""

usage() {
    printf '%s\n' "usage: $0 [--templates] [--mode host|client] [--env FILE]" >&2
}

validate_templates() {
    host="$TEMPLATES/host.env.example"
    client="$TEMPLATES/client.env.example"
    torrc="$TEMPLATES/torrc.onion-v3.example"
    for file in "$host" "$client" "$torrc"; do
        [ -f "$file" ] || { printf 'missing template: %s\n' "$(basename "$file")" >&2; return 1; }
        # Templates are public examples. Never inspect a Tor service directory.
        if grep -Eiq 'BEGIN .*PRIVATE KEY|hs_ed25519_secret_key|^[[:space:]]*[^#[:space:]]*PRIVATE_KEY=' "$file"; then
            printf 'private key material is forbidden in templates\n' >&2
            return 1
        fi
    done
    grep -Eq '^LOCALSCALE_ONION_MODE=host$' "$host" || return 1
    grep -Eq '^LOCALSCALE_ONION_MODE=client$' "$client" || return 1
    grep -Eq '^LOCALSCALE_ONION_HOSTNAME=' "$client" || return 1
    ! grep -Eq '^LOCALSCALE_ONION_HOSTNAME=' "$host" || return 1
    grep -Eq '^HiddenServiceVersion[[:space:]]+3$' "$torrc" || return 1
    grep -Eq '^HiddenServicePort[[:space:]]+80[[:space:]]+127\.0\.0\.1:8080$' "$torrc" || return 1
}

validate_env() {
    file=$1
    [ -f "$file" ] || { printf 'env file not found\n' >&2; return 1; }
    # GNU coreutils and BSD/macOS expose different stat flags. Prefer the
    # numeric GNU form, then fall back to the equivalent BSD form without
    # weakening the private-file check below.
    if permissions=$(stat -c '%a' "$file" 2>/dev/null); then
        :
    elif permissions=$(stat -f '%Lp' "$file" 2>/dev/null); then
        :
    else
        printf 'cannot inspect env file permissions\n' >&2
        return 1
    fi
    case "$permissions" in
        *[1-7][0-7]|*[0-7][1-7]) printf 'env file must not be group/world accessible\n' >&2; return 1 ;;
    esac
    # Read only deployment metadata. Key directories and files are never opened.
    mode_value=$(awk -F= '/^[[:space:]]*LOCALSCALE_ONION_MODE=/{print $2; exit}' "$file" || true)
    case "$mode_value" in host|client) ;; *) printf 'invalid LOCALSCALE_ONION_MODE\n' >&2; return 1 ;; esac
    if grep -Eiq '^[[:space:]]*(LOCALSCALE_ONION_)?(PRIVATE|SECRET|.*KEY)[A-Z_]*=' "$file"; then
        printf 'secret/key variables are not accepted\n' >&2
        return 1
    fi
    if [ "$mode_value" = client ]; then
        hostname=$(awk -F= '/^[[:space:]]*LOCALSCALE_ONION_HOSTNAME=/{print $2; exit}' "$file" || true)
        printf '%s\n' "$hostname" | grep -Eq '^[a-z2-7]{56}\.onion$|^replace-with-host-v3-onion-address\.onion$' || {
            printf 'client hostname must be a v3 .onion address\n' >&2; return 1;
        }
    else
        if grep -Eq '^[[:space:]]*LOCALSCALE_ONION_HOSTNAME=' "$file"; then
            printf 'host mode must not set LOCALSCALE_ONION_HOSTNAME\n' >&2
            return 1
        fi
    fi
}

check_templates=0
while [ "$#" -gt 0 ]; do
    case "$1" in
        --templates) check_templates=1; shift ;;
        --mode) [ "$#" -ge 2 ] || { usage; exit 2; }; mode=$2; shift 2 ;;
        --env) [ "$#" -ge 2 ] || { usage; exit 2; }; env_file=$2; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) usage; exit 2 ;;
    esac
done

[ "$check_templates" -eq 0 ] || validate_templates
if [ -n "$mode" ]; then
    case "$mode" in host|client) ;; *) printf 'invalid mode: %s\n' "$mode" >&2; exit 2 ;; esac
fi
[ -z "$env_file" ] || validate_env "$env_file"
printf '%s\n' 'LocalScale Onion validation passed (no Tor service or key files accessed).'
