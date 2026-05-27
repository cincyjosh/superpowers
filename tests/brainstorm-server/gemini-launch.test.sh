#!/usr/bin/env bash
# Verifies Gemini CLI launch behavior for the brainstorm server.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="${SUPERPOWERS_ROOT:-$(cd "$SCRIPT_DIR/../.." && pwd)}"
START_SCRIPT="$REPO_ROOT/skills/brainstorming/scripts/start-server.sh"
TEST_DIR="${TMPDIR:-/tmp}/brainstorm-gemini-test-$$"

cleanup() {
  rm -rf "$TEST_DIR"
}
trap cleanup EXIT

fail() {
  echo "FAIL: $1"
  echo "  $2"
  exit 1
}

mkdir -p "$TEST_DIR/fake-bin"
cat > "$TEST_DIR/fake-bin/node" <<'FAKENODE'
#!/usr/bin/env bash
echo "FOREGROUND_MODE=true"
exit 0
FAKENODE
chmod +x "$TEST_DIR/fake-bin/node"

output=$(
  env -u CODEX_CI -u MSYSTEM GEMINI_CLI=1 PATH="$TEST_DIR/fake-bin:$PATH" \
    bash "$START_SCRIPT" --project-dir "$TEST_DIR/session" 2>/dev/null
)

if [[ "$output" != *"FOREGROUND_MODE=true"* ]]; then
  fail "Gemini CLI auto-detects foreground mode" \
       "Expected foreground code path, output: $output"
fi

echo "PASS: Gemini CLI auto-detects foreground mode"
