#!/usr/bin/env bash
# cloud-upload.sh check CLOUD_URL
# cloud-upload.sh upload SUMMARY_JSON CLOUD_URL
#
# The optional gop Cloud upload of the gop Action (input cloud: "true", see
# docs/cloud.md). It sends only summary.json (gop summary, gop.summary/v1):
# never graph.json, the report or any credential of the scan.
#
# check  fails fast, before collection, when CLOUD_URL is not https:// (http://
#        only for localhost or 127.0.0.1) or the job cannot mint an OIDC token
#        (the workflow lacks "permissions: id-token: write").
# upload fetches a GitHub OIDC token with audience gop-cloud and POSTs the
#        summary to CLOUD_URL with it as a Bearer token.
#
# Neither token is ever printed or put on a command line: both reach curl
# through its stdin config, and the OIDC token is masked in the log. The
# response body is not printed (only the HTTP status).
set -euo pipefail

audience="gop-cloud"

die() { echo "gop action: cloud: $*" >&2; exit 1; }

check_url() {
  local url="$1"
  case "${url}" in
    "") die "cloud-url is required when cloud is \"true\"" ;;
    https://?*) ;;
    http://localhost:*/* | http://localhost/* | http://127.0.0.1:*/* | http://127.0.0.1/*) ;;
    *) die "cloud-url must start with https:// (got a value that does not)" ;;
  esac
  case "${url}" in
    *[[:space:]]* | *\"* | *\\*) die "cloud-url must not contain spaces, quotes or backslashes" ;;
  esac
}

check_oidc() {
  if [ -z "${ACTIONS_ID_TOKEN_REQUEST_URL:-}" ] || [ -z "${ACTIONS_ID_TOKEN_REQUEST_TOKEN:-}" ]; then
    die "this job cannot request a GitHub OIDC token. Add 'permissions: id-token: write' to the job or workflow that runs the gop Action (see docs/cloud.md), or set cloud: \"false\". Nothing was sent."
  fi
}

# proto limits curl to https, or http for the loopback test URLs.
proto() {
  case "$1" in
    http://*) echo "=http,https" ;;
    *) echo "=https" ;;
  esac
}

mode="${1:-}"
case "${mode}" in
  check)
    [ "$#" -eq 2 ] || die "usage: cloud-upload.sh check CLOUD_URL"
    check_url "$2"
    check_oidc
    echo "gop action: cloud: upload enabled; only summary.json will be sent (docs/cloud.md)"
    ;;
  upload)
    [ "$#" -eq 3 ] || die "usage: cloud-upload.sh upload SUMMARY_JSON CLOUD_URL"
    summary="$2"
    url="$3"
    check_url "${url}"
    check_oidc
    [ -s "${summary}" ] || die "${summary} is missing or empty"

    sep="?"
    case "${ACTIONS_ID_TOKEN_REQUEST_URL}" in *\?*) sep="&" ;; esac
    token_json="$(printf 'header = "Authorization: Bearer %s"\n' "${ACTIONS_ID_TOKEN_REQUEST_TOKEN}" |
      curl --config - --silent --show-error --fail --max-time 30 --retry 2 \
        --proto "$(proto "${ACTIONS_ID_TOKEN_REQUEST_URL}")" \
        "${ACTIONS_ID_TOKEN_REQUEST_URL}${sep}audience=${audience}")" ||
      die "could not get a GitHub OIDC token (check 'permissions: id-token: write'). Nothing was sent."
    # The JWT is base64url segments joined by dots: pick the "value" field
    # without jq, which not every runner has.
    token="$(printf '%s' "${token_json}" | tr -d '\r\n' | sed -n 's/.*"value"[[:space:]]*:[[:space:]]*"\([A-Za-z0-9._-]*\)".*/\1/p')"
    unset token_json
    [ -n "${token}" ] || die "the OIDC token response had no token. Nothing was sent."
    echo "::add-mask::${token}"

    resp="$(mktemp)"
    trap 'rm -f "${resp}"' EXIT
    status="$(printf 'header = "Authorization: Bearer %s"\n' "${token}" |
      curl --config - --silent --show-error --max-time 30 --retry 2 \
        --proto "$(proto "${url}")" \
        -X POST -H "Content-Type: application/json" -H "User-Agent: gop-action" \
        --data-binary "@${summary}" -o "${resp}" -w '%{http_code}' "${url}")" ||
      die "POST to cloud-url failed (network error)"
    unset token
    case "${status}" in
      2??) echo "gop action: cloud: summary uploaded (HTTP ${status})" ;;
      *) die "cloud-url answered HTTP ${status}; the summary was not accepted" ;;
    esac
    ;;
  *)
    die "usage: cloud-upload.sh check CLOUD_URL | upload SUMMARY_JSON CLOUD_URL"
    ;;
esac
