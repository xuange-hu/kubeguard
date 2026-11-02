# Security policy

## Scope

**kubeguard** — Kubernetes manifest audit with cross-resource analysis — is a static analysis tool: it reads **Kubernetes YAML manifests** and prints a report.
The security questions that apply to it are the ones that apply to any tool
that parses untrusted input.

Supported: the current release.

## What this tool does with your files

Nothing leaves your machine. There is no network client in the scanning path:
the tool opens the files you point it at, parses them, and writes a report.
It never writes to the files it reads.

## Reporting a vulnerability in kubeguard

Use [GitHub private vulnerability reporting](https://github.com/xuange-hu/kubeguard/security/advisories)
on the Security tab. If private reporting is unavailable to you, open an issue
marked `security`.

Include:

1. the version (`kubeguard --version`);
2. the input that triggers it — the actual file is preferred over a description;
3. what you expected and what happened.

For a parse failure, the smallest input that reproduces it is the whole report.

## What counts as a vulnerability here

- **A manifest construct that is parsed into the wrong shape.** The YAML reader is hand-written; a block that disappears produces a clean report on a manifest that is not clean.
- **An RBAC combination that is under-reported.** A role that can escalate is only visible when the rules are read together.
- **A line number that is off.** The report is evidence; wrong evidence is worse than none.
- **Unbounded work on a hostile manifest**, or a path escaping the directory it was pointed at.

## What does not count

- A rule firing on input you consider correct. That is a false positive: open
  an issue with the sample and it gets a regression test.
- A rule you want added. Open an issue or a PR.

## Timing

I triage within a week and will confirm receipt. If a fix needs to sit in a
branch for a while, the advisory goes out when the fix lands, not before.
