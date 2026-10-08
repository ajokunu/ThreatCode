# Security policy

## Reporting a vulnerability

Please report security vulnerabilities privately, through GitHub private vulnerability reporting.
Do not open a public issue, a pull request or a discussion for a vulnerability.

1. Open the [Security tab](https://github.com/ajokunu/ThreatCode/security) of the repository.
2. Choose **Report a vulnerability**.
3. Describe the problem, the version you used, and steps to reproduce it.
   A minimal input file that triggers the problem is the most useful thing you can attach.

Only the maintainer sees the report.
You will get a reply in the same thread, and the fix is prepared in a private advisory fork before anything is made public.
When a fix is released, the advisory is published and credits you unless you prefer to stay anonymous.

If the Security tab offers no **Report a vulnerability** button, private reporting is not enabled yet.
In that case open a public issue that says only that you have a security report and asks for a private channel, without any detail about the problem.

## What counts

ThreatCode reads files that other people wrote, so the interesting problems are in how it reads them.
These are in scope:

- a scanned file that makes ThreatCode execute code, read or write a file outside what the command names, follow a symlink out of the scan root, or contact a host;
- a scanned file that makes a scan hang or use unbounded memory or time past the documented limits;
- a way for a scanned repository to widen its own trust: turn off the gate, load its own rules, redirect the model client, or weaken redaction without a config file the user named;
- a secret value that appears in a report, a log or the model request;
- a bypass of the address checks on the model endpoint;
- output that injects markup, commands or workflow syntax into a pull request comment, a SARIF upload or a terminal.

A rule that misses a misconfiguration, or reports one that is not a problem, is a bug and not a vulnerability.
Please report it as a normal issue.

## Supported versions

Security fixes go to the latest release.

## How ThreatCode treats its own inputs

[The security model](https://github.com/ajokunu/ThreatCode/blob/main/docs/security-model.md) lists which inputs are trusted, the resource limits, the symlink policy and what the optional model review sends.
[Security](https://github.com/ajokunu/ThreatCode/blob/main/docs/security.md) describes the controls in detail.
