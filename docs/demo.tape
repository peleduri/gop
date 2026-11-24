# Records the README demo GIF on synthetic data only.
# Run from the repository root:  vhs docs/demo.tape
# Requires vhs (https://github.com/charmbracelet/vhs) and a gop binary on PATH
# (go install ./cmd/gop). No token and no network: the hidden setup unsets
# GITHUB_TOKEN and GH_TOKEN so doctor can never reach a real enterprise.
# The output is docs/assets/demo.gif; commit it with the change that moved it.

Output docs/assets/demo.gif

Require gop

Set Shell "bash"
Set FontSize 16
Set Width 1400
Set Height 860
Set Padding 24
Set Theme "Builtin Dark"
Set TypingSpeed 35ms

Hide
Type "unset GITHUB_TOKEN GH_TOKEN GOP_APP_ID GOP_APP_PRIVATE_KEY && export PS1='$ ' && clear"
Enter
Show

# 1. doctor is the preflight: before any API call it says which read-only
#    credential it needs, and never takes a token as a flag.
Type "gop doctor --enterprise acme"
Sleep 300ms
Enter
Sleep 4s

# 2. No token needed for the demo: the verdict.
Type "clear && gop report --demo --out - --format md | sed -n '1,9p'"
Sleep 300ms
Enter
Sleep 5s

# 3. AI agents in CI: an agent that anyone can start while it holds write and secrets.
Type "clear && gop report --demo --out - --format md | sed -n '/^## AI agents in CI/,/^## Suggested fixes/p' | head -22"
Sleep 300ms
Enter
Sleep 7s

# 4. The fewest changes that remove the most confirmed reach.
Type "clear && gop report --demo --out - --format md | sed -n '/^## Suggested fixes/,/^## Pinned/p'"
Sleep 300ms
Enter
Sleep 6s

# 5. The same report as HTML, the one in the README screenshot.
Type "clear && gop report --demo --out report.html && echo 'open report.html'"
Sleep 300ms
Enter
Sleep 3s
