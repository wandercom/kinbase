# Shared-data leak runbook

Status: candidate operational prerequisite. Owner: Company security steward.

This runbook covers the irreversible event that Personal/sensitive bytes are found
in Company or Git-carried Codebase state.

1. Stop new shared admissions and revoke the emitting principal/key at the Company
   cursor. Do not delete the originating evidence before preserving a restricted
   incident record.
2. Record exact event/payload digests, repository UUID, commits/refs/remotes known to
   contain them, Company cursors, caches, outbox receipts, and detection time. Never
   paste leaked bytes into ordinary tickets or logs.
3. Enumerate distribution: Company replicas/caches; Git server forks, pull requests,
   mirrors, CI artifacts, package/source archives, and known clone owners. Treat
   unknown clones as retained copies.
4. Notify the data owner, Company security steward, repository owner, and legal/privacy
   owner using the restricted incident channel. State that erasure cannot be proven.
5. Publish signed revocation/apology events so every reachable client withholds the
   leaked fact and its dependents. Rotate affected keys/tokens and invalidate caches.
6. The repository owner and legal/privacy owner jointly choose history rewrite versus
   preservation/disclosure. The tool never force-pushes or claims a rewrite erased
   clones. Record the chosen action and residual exposure.
7. Add the exact failure class as a regression canary and rerun the complete privacy
   gate. A clean rerun does not erase the incident from the proof history.

Before any non-private remote receives `.kin/` events, run at least 24 hours and 20
representative host sessions against a private canary repository with the same hooks,
approval path, and scanners. A commit-time tripwire scans staged `.kin/` bytes on
every shared repository. Soak/tripwire completion permits exposure testing; it is not
a general guarantee of non-disclosure.
