# Security policy

repo-sniff reads untrusted code on purpose, so the scanner itself is a
target. Reports about weaknesses in repo-sniff are welcome and taken
seriously.

## Reporting a vulnerability

Please **do not open a public issue** for a vulnerability.

Use GitHub's private reporting instead: open the
[Security tab](https://github.com/z3nghoul/repo-sniff/security) of the
repository and choose **Report a vulnerability**. Include:

- what you found and why it matters;
- the smallest repository, file or command that reproduces it (a synthetic
  one, not real malware);
- the repo-sniff version or commit and your operating system.

This is a small open-source project maintained by one person, so replies are
best effort. I aim to acknowledge a report within 7 days and will keep you
informed about the fix. Reporters are credited in the release notes unless
they prefer to stay anonymous.

## What counts as a vulnerability

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
- **A false "clean":** a way to make an incomplete scan exit with status 0, or
  to make a file the scanner did not read go unreported.
- **Supply chain:** a weakness in the CI workflows, release process or
  dependency pinning.

## What does not count

- A malicious repository that repo-sniff does not flag. That is a missed
  detection, not a vulnerability: please open a normal issue or pull request
  with a synthetic fixture. The honest list of blind spots is in
  [docs/DETECTIONS.md](docs/DETECTIONS.md).
- A false positive on a legitimate repository (a normal issue as well).

## Supported versions

Until 1.0 only the latest commit on `main` and the latest release receive
fixes.

## Safe testing

Please test against synthetic files you created yourself. Do not send real
malware samples, and do not run repo-sniff against repositories you have no
right to scan with the intent of causing harm.
