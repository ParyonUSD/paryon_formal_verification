#!/usr/bin/env bash
# Installs the pinned native Z3 release into .tools/z3 (git-ignored). The proof queries run in a native
# z3 process from SMT-LIB text (see src/z3.ts, checkNative); the wasm bindings stay for building
# expressions and for the small oracle/unit queries.
set -euo pipefail
VERSION="${Z3_VERSION:-5.1.0}"
ASSET="z3-${VERSION}-x64-glibc-2.39"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DEST="$ROOT/.tools"
if [ -x "$DEST/z3/bin/z3" ] && "$DEST/z3/bin/z3" --version | grep -q "$VERSION"; then
  echo "z3 $VERSION already installed at $DEST/z3/bin/z3"; exit 0
fi
mkdir -p "$DEST"
URL="https://github.com/Z3Prover/z3/releases/download/z3-${VERSION}/${ASSET}.zip"
echo "downloading $URL"
curl -sSL -o "$DEST/$ASSET.zip" "$URL"
rm -rf "$DEST/$ASSET" "$DEST/z3"
(cd "$DEST" && unzip -q "$ASSET.zip" && mv "$ASSET" z3 && rm "$ASSET.zip")
"$DEST/z3/bin/z3" --version
