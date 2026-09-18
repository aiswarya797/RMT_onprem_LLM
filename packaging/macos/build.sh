#!/bin/sh
set -eu

usage() {
  echo "usage: GO_BINARY=/absolute/path/to/go $0 development|release VERSION" >&2
  exit 2
}

[ "$#" -eq 2 ] || usage
MODE=$1
VERSION=$2
case "$MODE" in development|release) ;; *) usage ;; esac
case "$VERSION" in *[!0-9A-Za-z.-]*|"") echo "invalid version: $VERSION" >&2; exit 2 ;; esac

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PROJECT_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd)
GO_BINARY=${GO_BINARY:-}
[ -n "$GO_BINARY" ] || { echo "GO_BINARY must point to the verified Go 1.26.8 binary" >&2; exit 3; }
[ -x "$GO_BINARY" ] || { echo "GO_BINARY is not executable: $GO_BINARY" >&2; exit 3; }
GO_VERSION=$("$GO_BINARY" version)
case "$GO_VERSION" in "go version go1.26.8 darwin/arm64") ;; *) echo "release build requires go1.26.8 darwin/arm64; found: $GO_VERSION" >&2; exit 3 ;; esac

for TOOL in node npm pkgbuild productbuild pkgutil codesign xcrun lipo vtool shasum tar installer openssl awk grep; do
  command -v "$TOOL" >/dev/null 2>&1 || { echo "required tool missing: $TOOL" >&2; exit 3; }
done

SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-0}
case "$SOURCE_DATE_EPOCH" in *[!0-9]*|"") echo "SOURCE_DATE_EPOCH must be an integer" >&2; exit 2 ;; esac
BUILD_ID=${BUILD_ID:-development-local}
WORK_PARENT="$PROJECT_ROOT/.work/packaging"
mkdir -p "$WORK_PARENT"
WORK_ROOT=$(mktemp -d "$WORK_PARENT/$MODE-$VERSION.XXXXXX")
PAYLOAD_ROOT="$WORK_ROOT/payload"
APP_ROOT="$PAYLOAD_ROOT/Library/Application Support/LLM Monitor"
BIN_ROOT="$APP_ROOT/bin"
DOC_ROOT="$APP_ROOT/docs"
SHARE_ROOT="$APP_ROOT/share"
PACKAGE_ROOT="$WORK_ROOT/packages"
ARCHIVE_ROOT="$WORK_ROOT/archive/LLM Monitor"
DIST_ROOT="${DIST_DIR:-$PROJECT_ROOT/dist}"
OUTPUT_ROOT="$WORK_ROOT/output"
GOCACHE_ROOT="$PROJECT_ROOT/.work/u02-go/cache"
GOMODCACHE_ROOT="$PROJECT_ROOT/.work/u02-go/mod"
GOPATH_ROOT="$PROJECT_ROOT/.work/u02-go/path"
TMP_ROOT="$PROJECT_ROOT/.work/u02-go/tmp"

mkdir -p "$BIN_ROOT" "$DOC_ROOT" "$SHARE_ROOT" "$PACKAGE_ROOT" "$ARCHIVE_ROOT" "$DIST_ROOT" "$OUTPUT_ROOT" "$GOCACHE_ROOT" "$GOMODCACHE_ROOT" "$GOPATH_ROOT" "$TMP_ROOT"

if [ "$MODE" = release ]; then
  PKG_NAME="LLM-Monitor-$VERSION.pkg"
  TAR_NAME="LLM-Monitor-$VERSION-darwin-arm64.tar.gz"
else
  PKG_NAME="LLM-Monitor-$VERSION-development-unsigned.pkg"
  TAR_NAME="LLM-Monitor-$VERSION-development-adhoc-darwin-arm64.tar.gz"
fi
MANIFEST_NAME="LLM-Monitor-$VERSION-release-manifest.json"
SUMS_NAME="LLM-Monitor-$VERSION-SHA256SUMS"
INSTALLER_NAME="llm-monitor-install.sh"
SIGNATURE_NAME="$SUMS_NAME.sig"
PUBLIC_KEY_NAME="$SUMS_NAME.pub.pem"
EXPECTED_PUBLIC_KEY_SHA256=
EXPECTED_INSTALLER_IDENTITY=
if [ "$MODE" = release ]; then
  : "${RMT_EXPECTED_PUBLIC_KEY_SHA256:?RMT_EXPECTED_PUBLIC_KEY_SHA256 is required for release mode}"
  : "${RMT_EXPECTED_INSTALLER_IDENTITY:?RMT_EXPECTED_INSTALLER_IDENTITY is required for release mode}"
  EXPECTED_PUBLIC_KEY_SHA256=$RMT_EXPECTED_PUBLIC_KEY_SHA256
  EXPECTED_INSTALLER_IDENTITY=$RMT_EXPECTED_INSTALLER_IDENTITY
  [ "$EXPECTED_INSTALLER_IDENTITY" = "$DEVELOPER_ID_INSTALLER" ] || { echo "RMT_EXPECTED_INSTALLER_IDENTITY must match the independently published Developer ID Installer identity" >&2; exit 3; }
fi
for OUTPUT in "$PKG_NAME" "$TAR_NAME" "$MANIFEST_NAME" "$SUMS_NAME" "$SIGNATURE_NAME" "$PUBLIC_KEY_NAME" "$INSTALLER_NAME" "verify-release.sh"; do
  [ ! -e "$DIST_ROOT/$OUTPUT" ] || { echo "refusing to overwrite existing artifact: $DIST_ROOT/$OUTPUT" >&2; exit 7; }
done

if [ ! -d "$PROJECT_ROOT/web/node_modules" ]; then
  echo "web dependencies missing; run the documented npm ci command first" >&2
  exit 3
fi
npm_config_cache="$PROJECT_ROOT/.work/npm-cache" npm --prefix "$PROJECT_ROOT/web" run build

LDFLAGS="-s -w -X rmt.local/monitor/internal/protocol.Version=$VERSION -X rmt.local/monitor/internal/protocol.Build=$BUILD_ID"
for COMMAND in llm-monitor llm-monitor-collector; do
  CGO_ENABLED=1 GOOS=darwin GOARCH=arm64 MACOSX_DEPLOYMENT_TARGET=14.0 \
    CGO_CFLAGS="-O2 -g -mmacosx-version-min=14.0" CGO_LDFLAGS="-mmacosx-version-min=14.0" \
    GOTOOLCHAIN=local GOMAXPROCS=2 GOCACHE="$GOCACHE_ROOT" GOMODCACHE="$GOMODCACHE_ROOT" GOPATH="$GOPATH_ROOT" TMPDIR="$TMP_ROOT" \
    "$GO_BINARY" build -p 1 -tags sqlite_dbstat -trimpath -buildvcs=false -ldflags "$LDFLAGS" -o "$BIN_ROOT/$COMMAND" "$PROJECT_ROOT/cmd/$COMMAND"
  [ "$(lipo -archs "$BIN_ROOT/$COMMAND")" = "arm64" ] || { echo "$COMMAND is not an arm64-only binary" >&2; exit 8; }
  [ "$(vtool -show-build "$BIN_ROOT/$COMMAND" | awk '$1 == "minos" { print $2 }')" = "14.0" ] || { echo "$COMMAND does not declare macOS 14.0 as its minimum" >&2; exit 8; }
done

if [ "$MODE" = release ]; then
  : "${DEVELOPER_ID_APPLICATION:?DEVELOPER_ID_APPLICATION is required for release mode}"
  : "${DEVELOPER_ID_INSTALLER:?DEVELOPER_ID_INSTALLER is required for release mode}"
  : "${NOTARY_PROFILE:?NOTARY_PROFILE is required for release mode}"
  : "${CHECKSUM_SIGNING_KEY:?CHECKSUM_SIGNING_KEY is required for release mode}"
  for COMMAND in llm-monitor llm-monitor-collector; do
    codesign --force --options runtime --timestamp --sign "$DEVELOPER_ID_APPLICATION" "$BIN_ROOT/$COMMAND"
    codesign --verify --strict --verbose=2 "$BIN_ROOT/$COMMAND"
  done
  BINARY_TRUST=developer-id
else
  for COMMAND in llm-monitor llm-monitor-collector; do
    codesign --force --sign - "$BIN_ROOT/$COMMAND"
    codesign --verify --strict --verbose=2 "$BIN_ROOT/$COMMAND"
  done
  BINARY_TRUST=adhoc
fi

cp "$PROJECT_ROOT/docs/offline/install.html" "$DOC_ROOT/install.html"
cp "$PROJECT_ROOT/docs/offline/operate.html" "$DOC_ROOT/operate.html"
cp "$PROJECT_ROOT/docs/offline/recover.html" "$DOC_ROOT/recover.html"
cp "$PROJECT_ROOT/contracts/compatibility/v1/macos-15.5-m1-ollama-0.34.0.unverified.json" "$SHARE_ROOT/compatibility-unverified.json"

GOTOOLCHAIN=local GOMAXPROCS=2 GOCACHE="$GOCACHE_ROOT" GOMODCACHE="$GOMODCACHE_ROOT" GOPATH="$GOPATH_ROOT" TMPDIR="$TMP_ROOT" \
  "$GO_BINARY" list -deps -tags sqlite_dbstat -f '{{with .Module}}{{.Path}}|{{.Version}}|{{.Sum}}{{end}}' "$PROJECT_ROOT/cmd/llm-monitor" "$PROJECT_ROOT/cmd/llm-monitor-collector" \
    | awk 'NF && !seen[$0]++' > "$WORK_ROOT/go-modules.txt"
RMT_VERSION=$VERSION RMT_BUILD_ID=$BUILD_ID SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH \
  node "$PROJECT_ROOT/packaging/scripts/write-sbom.mjs" "$PROJECT_ROOT/web" "$WORK_ROOT/go-modules.txt" "$SHARE_ROOT/sbom.spdx.json"
node "$PROJECT_ROOT/packaging/scripts/write-notices.mjs" "$PROJECT_ROOT/web" "$PROJECT_ROOT/packaging/licenses" "$SHARE_ROOT/THIRD-PARTY-NOTICES.txt"

RMT_VERSION=$VERSION RMT_BUILD_ID=$BUILD_ID RMT_BUILD_MODE=$MODE RMT_GO_VERSION=$GO_VERSION \
RMT_NODE_VERSION=$(node --version) RMT_NPM_VERSION=$(npm --version) RMT_SDK_VERSION=$(xcrun --sdk macosx --show-sdk-version) \
RMT_MIN_MACOS=14.0 RMT_BINARY_TRUST=$BINARY_TRUST SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH \
  node "$PROJECT_ROOT/packaging/scripts/write-provenance.mjs" "$PROJECT_ROOT" "$BIN_ROOT" "$SHARE_ROOT/build-provenance.json"

cp -R "$APP_ROOT/." "$ARCHIVE_ROOT/"
NORMALIZED_TIME=$(date -r "$SOURCE_DATE_EPOCH" +%Y%m%d%H%M.%S)
find "$PAYLOAD_ROOT" "$WORK_ROOT/archive" -exec touch -h -t "$NORMALIZED_TIME" {} +

COPYFILE_DISABLE=1 pkgbuild --root "$PAYLOAD_ROOT" --identifier com.llm-monitor.payload --version "$VERSION" --min-os-version 14.0 \
  --install-location / --ownership recommended "$PACKAGE_ROOT/LLMMonitorPayload.pkg"
sed "s/@VERSION@/$VERSION/g" "$SCRIPT_DIR/Distribution.xml.in" > "$WORK_ROOT/Distribution.xml"

if [ "$MODE" = release ]; then
  COPYFILE_DISABLE=1 productbuild --distribution "$WORK_ROOT/Distribution.xml" --package-path "$PACKAGE_ROOT" \
    --sign "$DEVELOPER_ID_INSTALLER" --timestamp "$OUTPUT_ROOT/$PKG_NAME"
else
  COPYFILE_DISABLE=1 productbuild --distribution "$WORK_ROOT/Distribution.xml" --package-path "$PACKAGE_ROOT" "$OUTPUT_ROOT/$PKG_NAME"
fi

COPYFILE_DISABLE=1 tar -czf "$OUTPUT_ROOT/$TAR_NAME" -C "$WORK_ROOT/archive" "LLM Monitor"
pkgutil --payload-files "$OUTPUT_ROOT/$PKG_NAME" > "$WORK_ROOT/package-payload.txt"
grep -Ev '(^|/)\._' "$WORK_ROOT/package-payload.txt" > "$WORK_ROOT/package-product-payload.txt"
if grep -Ev '^(\.|\./Library|\./Library/Application Support|\./Library/Application Support/LLM Monitor)(/.*)?$' "$WORK_ROOT/package-product-payload.txt"; then
  echo "package contains a path outside the current-user LLM Monitor root" >&2
  exit 8
fi
for REQUIRED_PAYLOAD in \
  "./Library/Application Support/LLM Monitor/bin/llm-monitor" \
  "./Library/Application Support/LLM Monitor/bin/llm-monitor-collector" \
  "./Library/Application Support/LLM Monitor/docs/install.html" \
  "./Library/Application Support/LLM Monitor/docs/operate.html" \
  "./Library/Application Support/LLM Monitor/docs/recover.html" \
  "./Library/Application Support/LLM Monitor/share/compatibility-unverified.json" \
  "./Library/Application Support/LLM Monitor/share/sbom.spdx.json" \
  "./Library/Application Support/LLM Monitor/share/build-provenance.json" \
  "./Library/Application Support/LLM Monitor/share/THIRD-PARTY-NOTICES.txt"
do
  grep -Fqx "$REQUIRED_PAYLOAD" "$WORK_ROOT/package-product-payload.txt" || { echo "package is missing required payload: $REQUIRED_PAYLOAD" >&2; exit 8; }
done
installer -dominfo -pkg "$OUTPUT_ROOT/$PKG_NAME" > "$WORK_ROOT/installer-domains.txt"
grep -q "CurrentUserHomeDirectory" "$WORK_ROOT/installer-domains.txt" || { echo "package does not enable CurrentUserHomeDirectory" >&2; exit 8; }
if grep -q "LocalSystem" "$WORK_ROOT/installer-domains.txt"; then
  echo "package unexpectedly enables LocalSystem" >&2
  exit 8
fi

NOTARY_SUBMISSION_ID=
if [ "$MODE" = release ]; then
  NOTARY_RESULT="$WORK_ROOT/notary-result.json"
  xcrun notarytool submit "$OUTPUT_ROOT/$PKG_NAME" --keychain-profile "$NOTARY_PROFILE" --wait --output-format json > "$NOTARY_RESULT"
  NOTARY_STATUS=$(/usr/bin/plutil -extract status raw -o - "$NOTARY_RESULT")
  [ "$NOTARY_STATUS" = "Accepted" ] || { echo "notarization was not accepted: $NOTARY_STATUS" >&2; exit 8; }
  NOTARY_SUBMISSION_ID=$(/usr/bin/plutil -extract id raw -o - "$NOTARY_RESULT")
  xcrun stapler staple -v "$OUTPUT_ROOT/$PKG_NAME"
  xcrun stapler validate -v "$OUTPUT_ROOT/$PKG_NAME"
  pkgutil --check-signature "$OUTPUT_ROOT/$PKG_NAME" > "$WORK_ROOT/package-signature.txt"
  grep -q "Status: signed by a certificate trusted by macOS" "$WORK_ROOT/package-signature.txt" || { echo "trusted installer signature not verified" >&2; exit 8; }
  spctl --assess --type install --verbose=2 "$OUTPUT_ROOT/$PKG_NAME"
  PACKAGE_TRUST=developer-id
  NOTARIZATION=accepted-stapled-validated
  CHECKSUM_SIGNATURE=openssl-sha256
else
  PACKAGE_TRUST=unsigned
  NOTARIZATION=not-submitted
  CHECKSUM_SIGNATURE=none
fi

RMT_VERSION=$VERSION RMT_BUILD_ID=$BUILD_ID RMT_BUILD_MODE=$MODE RMT_BINARY_TRUST=$BINARY_TRUST \
RMT_PACKAGE_TRUST=$PACKAGE_TRUST RMT_NOTARIZATION=$NOTARIZATION RMT_NOTARY_SUBMISSION_ID=$NOTARY_SUBMISSION_ID \
RMT_APPLICATION_IDENTITY=${DEVELOPER_ID_APPLICATION:-} RMT_INSTALLER_IDENTITY=${DEVELOPER_ID_INSTALLER:-} \
RMT_CHECKSUM_SIGNATURE=$CHECKSUM_SIGNATURE \
  node "$PROJECT_ROOT/packaging/scripts/write-release-manifest.mjs" "$OUTPUT_ROOT" "$OUTPUT_ROOT/$MANIFEST_NAME" "$PKG_NAME" "$TAR_NAME"

(cd "$OUTPUT_ROOT" && shasum -a 256 "$PKG_NAME" "$TAR_NAME" "$MANIFEST_NAME") > "$OUTPUT_ROOT/$SUMS_NAME"
if [ "$MODE" = release ]; then
  openssl pkey -in "$CHECKSUM_SIGNING_KEY" -pubout -out "$OUTPUT_ROOT/$SUMS_NAME.pub.pem"
  openssl dgst -sha256 -sign "$CHECKSUM_SIGNING_KEY" -out "$OUTPUT_ROOT/$SUMS_NAME.sig" "$OUTPUT_ROOT/$SUMS_NAME"
  openssl dgst -sha256 -verify "$OUTPUT_ROOT/$SUMS_NAME.pub.pem" -signature "$OUTPUT_ROOT/$SUMS_NAME.sig" "$OUTPUT_ROOT/$SUMS_NAME"
  ACTUAL_PUBLIC_KEY_SHA256=$(shasum -a 256 "$OUTPUT_ROOT/$PUBLIC_KEY_NAME" | awk '{print $1}')
  [ "$ACTUAL_PUBLIC_KEY_SHA256" = "$EXPECTED_PUBLIC_KEY_SHA256" ] || { echo "checksum public key does not match RMT_EXPECTED_PUBLIC_KEY_SHA256" >&2; exit 8; }
fi

sed_escape() {
  printf '%s' "$1" | sed 's/[\\&|]/\\&/g'
}
SAFE_MODE=$(sed_escape "$MODE")
SAFE_VERSION=$(sed_escape "$VERSION")
SAFE_PACKAGE_NAME=$(sed_escape "$PKG_NAME")
SAFE_SUMS_NAME=$(sed_escape "$SUMS_NAME")
SAFE_SIGNATURE_NAME=$(sed_escape "$SIGNATURE_NAME")
SAFE_PUBLIC_KEY_NAME=$(sed_escape "$PUBLIC_KEY_NAME")
SAFE_EXPECTED_PUBLIC_KEY_SHA256=$(sed_escape "$EXPECTED_PUBLIC_KEY_SHA256")
SAFE_EXPECTED_INSTALLER_IDENTITY=$(sed_escape "$EXPECTED_INSTALLER_IDENTITY")
sed \
  -e "s|@MODE@|$SAFE_MODE|g" \
  -e "s|@VERSION@|$SAFE_VERSION|g" \
  -e "s|@PACKAGE_NAME@|$SAFE_PACKAGE_NAME|g" \
  -e "s|@SUMS_NAME@|$SAFE_SUMS_NAME|g" \
  -e "s|@SIGNATURE_NAME@|$SAFE_SIGNATURE_NAME|g" \
  -e "s|@PUBLIC_KEY_NAME@|$SAFE_PUBLIC_KEY_NAME|g" \
  -e "s|@EXPECTED_PUBLIC_KEY_SHA256@|$SAFE_EXPECTED_PUBLIC_KEY_SHA256|g" \
  -e "s|@EXPECTED_INSTALLER_IDENTITY@|$SAFE_EXPECTED_INSTALLER_IDENTITY|g" \
  "$SCRIPT_DIR/install.sh.in" > "$OUTPUT_ROOT/$INSTALLER_NAME"
chmod 755 "$OUTPUT_ROOT/$INSTALLER_NAME"
if [ "$MODE" = release ]; then
  cp "$SCRIPT_DIR/verify-release.sh" "$OUTPUT_ROOT/verify-release.sh"
  chmod 755 "$OUTPUT_ROOT/verify-release.sh"
fi

for OUTPUT in "$PKG_NAME" "$TAR_NAME" "$MANIFEST_NAME" "$SUMS_NAME"; do
  mv "$OUTPUT_ROOT/$OUTPUT" "$DIST_ROOT/$OUTPUT"
done
if [ "$MODE" = release ]; then
  mv "$OUTPUT_ROOT/$SIGNATURE_NAME" "$DIST_ROOT/$SIGNATURE_NAME"
  mv "$OUTPUT_ROOT/$PUBLIC_KEY_NAME" "$DIST_ROOT/$PUBLIC_KEY_NAME"
  mv "$OUTPUT_ROOT/verify-release.sh" "$DIST_ROOT/verify-release.sh"
fi
mv "$OUTPUT_ROOT/$INSTALLER_NAME" "$DIST_ROOT/$INSTALLER_NAME"

echo "Built $MODE artifacts in $DIST_ROOT"
if [ "$MODE" = development ]; then
  echo "Development output is ad-hoc/unsigned, not notarized, and not a qualified customer release."
fi
