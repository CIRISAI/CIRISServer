#!/bin/sh
# CIRIS for macOS: wrap a staged desktop payload as CIRIS.app in a .dmg.
#
#   installers/desktop/macos/build_app.sh <staged payload dir> <version> <out dir>
#
# The payload lives in CIRIS.app/Contents/Resources/payload; the app's executable
# runs payload.json's launch_argv from there. The agent's in-place upgrade writes
# into that payload, so the app must stay where the user can write it
# (/Applications for an admin user, or ~/Applications).
#
# UNSIGNED for 2.24 (Eric 2026-11-27): Gatekeeper will say the app is from an
# unidentified developer; right-click > Open the first time. SIGNING goes in the
# marked step below once an Apple Developer ID exists (codesign --deep with the
# hardened runtime, then notarytool and stapler on the .dmg).
set -eu

payload=$1
version=$2
out=$3
[ -f "$payload/payload.json" ] || { echo "build_app.sh: $payload holds no payload.json" >&2; exit 1; }

work=$(mktemp -d)
app="$work/CIRIS.app"
mkdir -p "$app/Contents/MacOS" "$app/Contents/Resources"
cp -a "$payload" "$app/Contents/Resources/payload"

cat > "$app/Contents/MacOS/CIRIS" <<'EOF'
#!/bin/sh
# CIRIS.app: payload.json launch_argv, run from the payload directory. Never the
# payload's bin/ciris-agent (it names the build machine's interpreter), never
# -I or -s (ciris-no-user-site.pth keeps the user site out).
here=$(cd "$(dirname "$0")/../Resources/payload" && pwd)
cd "$here"
exec "$here/python/bin/python3" -m ciris_engine.cli "$@"
EOF
chmod +x "$app/Contents/MacOS/CIRIS"

cat > "$app/Contents/Info.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleName</key><string>CIRIS</string>
  <key>CFBundleDisplayName</key><string>CIRIS</string>
  <key>CFBundleIdentifier</key><string>ai.ciris.desktop</string>
  <key>CFBundleVersion</key><string>$version</string>
  <key>CFBundleShortVersionString</key><string>$version</string>
  <key>CFBundleExecutable</key><string>CIRIS</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>LSMinimumSystemVersion</key><string>12.0</string>
  <key>NSHighResolutionCapable</key><true/>
  <key>NSMicrophoneUsageDescription</key><string>CIRIS uses the microphone for calls.</string>
  <key>NSCameraUsageDescription</key><string>CIRIS uses the camera for video calls.</string>
</dict>
</plist>
EOF

# SIGNING: not yet (2.24 ships unsigned). With a Developer ID:
#   codesign --force --deep --options runtime --sign "$CIRIS_MAC_IDENTITY" "$app"
#   (then notarize and staple the .dmg below)

mkdir -p "$out"
arch=$(python3 -c "import json;print(json.load(open('$payload/payload.json'))['target'])")
dmg="$out/CIRIS-$version-$arch.dmg"
ln -s /Applications "$work/Applications"
hdiutil create -volname "CIRIS $version" -srcfolder "$work" -ov -format UDZO "$dmg" >/dev/null
rm -rf "$work"
echo "$dmg"
