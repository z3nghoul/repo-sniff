SYNTHETIC TEST FIXTURE — not functional

# demo project

A made-up "take-home test" project scanned in the README demo
(`docs/demo.gif`). It imitates the shape of a known lure (an auto-run VS Code
task, an install hook chain, an obfuscated config, a loader that evaluates a
downloaded string) and does nothing: the task echoes a word, the URL is on the
`.invalid` domain.

To record the demo again, install [vhs](https://github.com/charmbracelet/vhs)
and run from the repository root:

```sh
cargo install --path crates/repo-sniff
vhs docs/demo.tape
```
