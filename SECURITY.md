# security policy

How to report a weakness in repo-sniff itself, and what counts as one.
repo-sniff reads untrusted code on purpose, so the scanner itself is a
target; such reports are welcome and taken seriously.

## reporting a vulnerability

Please **do not open a public issue** for a vulnerability.

Use GitHub's private reporting instead: open the
[Security tab](https://github.com/z3nghoul/repo-sniff/security) of the
repository and choose **Report a vulnerability**. Include:

- what you found and why it matters;
- the smallest repository, file or command that reproduces it (a synthetic
  one, not real malware);
- the repo-sniff version (`repo-sniff --version`) or commit and your
  operating system.

This is a small open-source project maintained by one person, so replies are
best effort. I aim to acknowledge a report within 7 days and will keep you
informed about the fix. Reporters are credited in the release notes unless
they prefer to stay anonymous.

## what counts as a vulnerability

Problems where a scanned repository, or a third-party file the scanner loads,
can attack or mislead the scanner:

- **Code execution:** anything that makes repo-sniff run code from the
  scanned repository (install, build, scripts, hooks, filters, `eval`).
- **Leaving the sandbox of the scan:** following a symlink out of the
  repository, reading or writing files outside the scanned directory and the
  scanner's own temporary directories.
- **Resource exhaustion:** a crafted repository that makes the scanner hang,
  crash or use unbounded memory or disk (zip bombs, huge files, catastrophic
  patterns, deep recursion), bypassing the documented limits.
- **Report spoofing:** content from the scanned repository or from a locale
  file that hides findings, forges findings, or injects terminal escape
  sequences into the output.
- **Unsafe cloning:** a way to make the clone step run a filter, hook or
  helper, read the user's git configuration or environment, ask a question
  interactively, fetch over anything but https, or print a credential.
- **A false "clean":** a way to make an inconclusive scan (file limit reached,
  a file not read, an executable binary not analyzed) exit with status 0, or to
  make a file the scanner did not analyze go unreported.
- **Supply chain:** a weakness in the CI workflows, release process or
  dependency pinning.

The guarantees these break are listed in
[docs/DETECTIONS.md](docs/DETECTIONS.md#5-scanner-hardening).

## what does not count

These are normal issues, with their own templates:

- A malicious repository that repo-sniff does not flag is a missed detection:
  open a [missed detection](https://github.com/z3nghoul/repo-sniff/issues/new?template=missed-detection.yml)
  issue or a pull request with a synthetic fixture. The known gaps of every
  rule are in [docs/DETECTIONS.md](docs/DETECTIONS.md).
- A finding on a legitimate repository is a
  [false positive](https://github.com/z3nghoul/repo-sniff/issues/new?template=false-positive.yml).

## supported versions

Until 1.0 only the latest commit on `main` and the latest release receive
fixes.

## safe testing

Please test against synthetic files you created yourself. Do not send real
malware samples, and do not run repo-sniff against repositories you have no
right to scan with the intent of causing harm.
