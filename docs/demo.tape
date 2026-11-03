# Demo for the README. Needs vhs (https://github.com/charmbracelet/vhs) and a
# `repo-sniff` on PATH (cargo install --path crates/repo-sniff). Run it from the
# repository root:  vhs docs/demo.tape
Output docs/demo.gif

Set Theme "Catppuccin Mocha"
Set FontSize 15
Set Width 1300
Set Height 760
Set Padding 16
Set TypingSpeed 40ms
Set PlaybackSpeed 1

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
