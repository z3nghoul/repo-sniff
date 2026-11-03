# Demo for the README. Needs vhs (https://github.com/charmbracelet/vhs) and a
# `repo-sniff` on PATH (cargo install --path crates/repo-sniff). Run it from the
# repository root:  vhs docs/demo.tape
#
# The demo repository is stored defanged (see docs/demo/README.md), so the tape
# first writes the real one to a temporary folder (the ignored test below does
# that) and scans it from there; the report is the same as for the original, undefanged demo.
Output docs/demo.gif

Set Theme "Catppuccin Mocha"
Set FontSize 15
Set Width 1300
Set Height 760
Set Padding 16
Set TypingSpeed 40ms
Set PlaybackSpeed 1

Hide
Type "T=$(mktemp -d); REPO_SNIFF_DEMO_DIR=$T/docs/demo cargo test -q -p repo-sniff-core --test fixture_expectations materialize_demo -- --ignored >/dev/null && cd $T && echo DEMO-$((1+1))"
Enter
Wait@120s /DEMO-2/
Type "clear"
Enter
Show

Type "# a made-up take-home test, see docs/demo/"
Enter
Sleep 600ms
Type "repo-sniff scan docs/demo"
Enter
Sleep 5s

Hide
Type "clear"
Enter
Show

Type "# and a real, honest repository"
Enter
Sleep 600ms
Type "repo-sniff scan https://github.com/rust-lang/cargo"
Enter
Sleep 12s

Hide
Type "cd; rm -rf $T"
Enter
Show
