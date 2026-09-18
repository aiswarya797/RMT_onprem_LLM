#!/bin/sh
set -eu

[ "$#" -eq 6 ] || {
  echo "usage: $0 PACKAGE SHA256SUMS SHA256SUMS.sig SHA256SUMS.pub.pem EXPECTED_PUBLIC_KEY_SHA256 EXPECTED_INSTALLER_IDENTITY" >&2
  exit 2
}
PKG=$1
SUMS=$2
SIGNATURE=$3
PUBLIC_KEY=$4
EXPECTED_PUBLIC_KEY_SHA256=$5
EXPECTED_INSTALLER_IDENTITY=$6

for FILE in "$PKG" "$SUMS" "$SIGNATURE" "$PUBLIC_KEY"; do
  [ -f "$FILE" ] || { echo "missing file: $FILE" >&2; exit 2; }
done

ACTUAL_PUBLIC_KEY_SHA256=$(shasum -a 256 "$PUBLIC_KEY" | awk '{print $1}')
[ "$ACTUAL_PUBLIC_KEY_SHA256" = "$EXPECTED_PUBLIC_KEY_SHA256" ] || { echo "checksum public key fingerprint does not match the independently published value" >&2; exit 8; }
openssl dgst -sha256 -verify "$PUBLIC_KEY" -signature "$SIGNATURE" "$SUMS"
PKG_BASENAME=$(basename -- "$PKG")
EXPECTED_PKG_SHA256=$(awk -v name="$PKG_BASENAME" '$2 == name {print $1}' "$SUMS")
[ -n "$EXPECTED_PKG_SHA256" ] || { echo "supplied package is not named in the signed checksum list" >&2; exit 8; }
[ "$(printf '%s\n' "$EXPECTED_PKG_SHA256" | wc -l | tr -d ' ')" = "1" ] || { echo "signed checksum list has duplicate package entries" >&2; exit 8; }
[ "${#EXPECTED_PKG_SHA256}" -eq 64 ] || { echo "signed checksum list has an invalid package digest" >&2; exit 8; }
case "$EXPECTED_PKG_SHA256" in *[!0-9a-f]*) echo "signed checksum list has an invalid package digest" >&2; exit 8;; esac
ACTUAL_PKG_SHA256=$(shasum -a 256 "$PKG" | awk '{print $1}')
[ "$ACTUAL_PKG_SHA256" = "$EXPECTED_PKG_SHA256" ] || { echo "supplied package does not match its signed checksum entry" >&2; exit 8; }
SIGNATURE_REPORT=$(pkgutil --check-signature "$PKG")
printf '%s\n' "$SIGNATURE_REPORT"
ACTUAL_INSTALLER_IDENTITY=$(printf '%s\n' "$SIGNATURE_REPORT" | awk 'sub(/^[[:space:]]*1[.][[:space:]]*/, "") { print; exit }')
[ "$ACTUAL_INSTALLER_IDENTITY" = "$EXPECTED_INSTALLER_IDENTITY" ] || { echo "installer identity does not match the independently published identity" >&2; exit 8; }
xcrun stapler validate -v "$PKG"
spctl --assess --type install --verbose=2 "$PKG"
installer -dominfo -pkg "$PKG"

echo "Release package checks passed against the independently supplied public-key fingerprint and installer identity."
