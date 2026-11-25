# Enterprise-TLS v0.3.0

## What's Changed

### Native enrollment

- Enrollment now runs in process, with no child process. A machine ECDSA P-256
  key is created with `github.com/keppin-oss/cng` v0.4.0, the PKCS #10 request
  is built in Go, and the CA is called through the in-process `ICertRequest`
  COM interface.
- The new `lifecycle` package drives each attempt through a durable state
  machine (`lifecycle.Enrollment`, `Start`/`Step`) on a checksummed journal in
  a directory that only SYSTEM and Administrators can access. After a crash the
  last durable record selects the recovery path, and non-repeatable effects
  are never repeated:
  - a key is adopted only from a recorded create result;
  - a submit whose result was lost is never resubmitted; the attempt ends
    `CA_UNKNOWN`;
  - an install is never repeated; only the binding check proves it.
- Outcomes: `ACCEPTED`, `DENIED`, `BLOCKED_PKI`, `CA_UNKNOWN`, `INCONCLUSIVE`,
  `ABANDONED_UNVERIFIED`, `ABORTED_PRE_SUBMIT`. `BLOCKED_PKI`, `CA_UNKNOWN` and
  `INCONCLUSIVE` block new attempts until an administrator records an
  `AttemptResolution` with `lifecycle.Resolver.ResolveAttempt`.
- `ACCEPTED` means installed in `LocalMachine\My` with a proven binding to the
  key. It does not mean the certificate is in use.
- Every other outcome closes with a terminal cleanup plan and a result per
  artifact. Keys are deleted with cng's verified delete.
- New adapters in package `enterprise`: `NewCNGKeys`, `NewNativeRequester`,
  `NewMachineMy`, `NewAttemptDeleter`, `EnrollmentValidator`. New error
  `ErrCallerIdentity`: the CA call runs only as the expected identity
  (LocalSystem in the example) and without impersonation.
- New example: `examples/native-enroll`.
- The new APIs also include a process guard with a durable crash latch
  (`lifecycle.ProcessGuard`), consumer-side activation fencing
  (`lifecycle.Activator`), journal compaction with archiving
  (`FileJournal.Compact`) and administrative resolutions (`lifecycle.Resolver`).

### Deprecated

- `Provider`, `New`, `NewWithProcessJournal`, `Provider.Enroll` and
  `BuildRequestINF` (the `certreq.exe` path) are deprecated. They keep working
  in this release and will be removed in a later breaking release. `Uninstall`
  and `ValidateCertificate` are not deprecated.

### Behavior changes on the deprecated `certreq.exe` path

- An RPC/DNS failure during `-submit` (`0x800706BA`, `0x800706D9`,
  `0x80072EE7`) is now `StatusEnrollmentFailed` / `ErrEnrollmentFailed`, no
  longer `StatusUnavailable`. `StatusUnavailable` / `ErrUnavailable` now means
  only that `certreq.exe` is missing. Callers that used `ErrUnavailable` to
  trigger a fallback must not treat these failures as unavailability.
- A request left pending by the CA returns the new `StatusEnrollmentPending` /
  `ErrEnrollmentPending` with the new `KeyStateRetained`; the key, the request
  object and the attempt files are kept. It was previously reported as a
  failure. `ErrEnrollmentPending` does not match `ErrEnrollmentFailed`.
- `certreq.exe` is run only from the Windows system directory, never resolved
  through `PATH`.
- `Template` is written as `CertificateTemplate` in `[RequestAttributes]`, and
  `-submit` no longer passes `-machine`. Both previously made `Enroll` fail
  against a real Enterprise CA.
- Each tool process runs in a Job Object; when quiescence of the process tree
  cannot be established, the new `ErrProcessQuiescence` keeps the attempt files
  and reports the key as `KeyStateUnproven`.
- `NewWithProcessJournal` (new, already deprecated) adds a durable crash latch;
  a blocked call returns the new `ErrOperationBlocked`.
- New `Result` fields: `ArtifactDirectory`, `CA`, `RequestID`.

See [Upgrading from v0.2.0](README.md#15-upgrading-from-v020).

## Compatibility

- Go 1.26.8
- golang.org/x/sys v0.48.0
- github.com/keppin-oss/cng v0.4.0
- Windows/amd64. The native path needs a domain member running the broker as
  LocalSystem and a template that accepts an ECDSA P-256 key.

## Validation

- Offline: build and vet on Windows and Linux; the test suite passed, including
  the crash matrix of the state machine on the real NTFS journal with an
  elevated token.
- Live, against an AD CS Enterprise CA, on Windows 11 Pro (build 26200) and
  Windows Server 2025 Standard (build 26100), domain members, with one signed
  build, Microsoft Defender Antivirus, attack surface reduction rules in audit
  and then block mode, Sysmon and CA auditing:
  - issued, denied and pending requests, and a CA service suspended during the
    submit;
  - the CA recorded the computer account as requester and a request equal to
    the CSR;
  - key export was refused, and only the target service could use the key;
  - no child process; network connections only to the CA;
  - no Defender or ASR event for the module's process.
- The live runs used a build made before the final cleanup of comments and
  texts. That cleanup changed two report reasons (`BLOCKED_PKI` and the
  validation failures), one error text and the persisted value of the
  risk-acceptance decision (now `RISK_ACCEPTED`). The published tree is
  therefore not the exact tree validated live. The offline suite, with an
  elevated token, passed again on the published source. The non-elevated suite
  also passed with the race detector (`-race -count=2`).
- Not validated: other Windows builds or editions, other key storage
  providers, Defender for Endpoint, WDAC or AppLocker policies, power loss
  during a journal write, the elevated tests under the race detector.

## Known limitations

- A CA call that does not return cannot be cancelled in process; the attempt
  ends `CA_UNKNOWN` and needs a resolution.
- No administrative tooling is included for resolutions or journal archiving.
- Opening the key for TLS serving, activation, rotation and renewal are
  consumer responsibilities. The technical reference describes how to open the
  key of an `ACCEPTED` attempt with cng.
