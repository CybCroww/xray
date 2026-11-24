#!/usr/bin/env bash
set -euo pipefail

if [[ $(uname -s) != Darwin ]] || ! xcodebuild -version >/dev/null; then
  echo 'Xcode on macOS is required to link the Apple framework.' >&2
  exit 1
fi

cd "$(dirname "${BASH_SOURCE[0]}")/../.."
output=${1:-"$PWD/build_assets/CVPNCore.xcframework"}
[[ "$output" = /* ]] || output="$PWD/$output"
[[ "${output##*/}" = CVPNCore.xcframework && ! -e "$output" ]] || {
  echo 'Use a new output path ending in CVPNCore.xcframework.' >&2
  exit 1
}

scratch=$(mktemp -d "${TMPDIR:-/tmp}/cvpn-ios.XXXXXXXX")
trap 'rm -rf "$scratch"' EXIT
mobile_version=$(go list -m -f '{{.Version}}' golang.org/x/mobile)
GOBIN="$scratch" go install "golang.org/x/mobile/cmd/gomobile@$mobile_version"
GOBIN="$scratch" go install "golang.org/x/mobile/cmd/gobind@$mobile_version"
PATH="$scratch:$PATH" "$scratch/gomobile" bind -target=ios,iossimulator -iosversion=15.0 \
  -prefix=CVPN -trimpath -ldflags='-s -w -checklinkname=0' \
  -o "$scratch/CVPNCore.xcframework" ./mobile

# Verify that Xcode can import the output and compile the actual extension bridge.
sdk=$(xcrun --sdk iphoneos --show-sdk-path)
bridge="$PWD/mobile/ios/CVPNPacketFlow.m"
xcrun --sdk iphoneos clang -target arm64-apple-ios15.0 -isysroot "$sdk" -fobjc-arc -fmodules \
  -F"$scratch/CVPNCore.xcframework/ios-arm64" -Wall -Wextra -Werror -c "$bridge" -o "$scratch/CVPNPacketFlow.o"

mkdir -p "$(dirname "$output")"
mv "$scratch/CVPNCore.xcframework" "$output"
printf '%s\n' "$output"
