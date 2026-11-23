# Records the README demo on the synthetic acme fixture.
# Run from the repository root:  vhs docs/demo.tape
# Requires vhs (https://github.com/charmbracelet/vhs) and a gop binary on PATH
# (go install ./cmd/gop). Uses synthetic data only.

Output docs/assets/demo.gif

Require gop

Set Shell "bash"
Set FontSize 16
Set Width 1400
Set Height 820
Set Padding 24
Set Theme "Builtin Dark"
Set TypingSpeed 35ms

Hide
Type "export PS1='$ ' && clear"
Enter
Show

# 1. One path from acme-actions members to a cloud OIDC trust in another org.
Type "gop paths --graph testdata/acme/graph.json --from members:acme-actions --to oidc:acme-app/web"
Sleep 300ms
Enter
Sleep 4s

# 2. The headline and the fix plan.
Type "clear && gop report --graph testdata/acme/graph.json --out - --format md | head -30"
Sleep 300ms
Enter
Sleep 6s

# 3. A path gop could not fully see: possible, not absent.
Type "clear && gop who --graph testdata/acme/graph.json --target secret:acme-legacy/old-api"
Sleep 300ms
Enter
Sleep 5s
