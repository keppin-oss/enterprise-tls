# Enterprise-TLS v0.4.0

This is a breaking release: the `certreq.exe` path, deprecated in v0.3.0, is
removed. Enrollment runs only through `lifecycle.Enrollment` with the native
adapters.

## What's Changed

### Removed: the `certreq.exe` path

The following identifiers of package `enterprise` are removed without
replacement:

- `Provider`, `New`, `Provider.Enroll`, `NewWithProcessJournal`, `Config`;
- `Result`, `Status` and its `Status*` constants, `KeyState` and its
  `KeyState*` constants;
- `CleanupInfo`, `Uninstall`;
- `BuildRequestINF`;
- the sentinel errors `ErrNotConfigured`, `ErrUnavailable`,
  `ErrEnrollmentFailed`, `ErrEnrollmentIncomplete`, `ErrEnrollmentPending`,
  `ErrProcessQuiescence`, `ErrOperationBlocked`, `ErrCleanupFailed`,
  `ErrOwnershipMismatch`.

The examples `examples/enroll`, `examples/uninstall` and
`examples/classification` are removed with them. The module no longer runs
`certreq.exe` or any other child process.

Use `lifecycle.Enrollment` with `NewCNGKeys`, `NewNativeRequester`,
`NewMachineMy`, `NewAttemptDeleter` and `EnrollmentValidator`
([`examples/native-enroll`](../examples/native-enroll/main.go)). The cleanup of
an attempt's key and files is part of its terminal cleanup plan. Keys and
certificates enrolled by the old `certreq.exe` path are not handled by this
module.

### cng v0.5.1

- `github.com/keppin-oss/cng` moves from v0.4.0 to v0.5.1. `CNGKeys` creates,
  opens and deletes keys with `windowscng.Create`, `Open` and `Delete` and the
  configured service's `ServicePolicy`.
- The outcomes of the key adapter are unchanged: an existing key is
  `lifecycle.ErrKeyExists`, a missing key on delete is `lifecycle.ErrNotFound`,
  a key that fails verification is `lifecycle.ErrNotOwned`. A delete still
  verifies the policy and the public key recorded in the journal on the handle
  it deletes.
- Inherited from cng v0.5: the policy check is exact. A key with extra access
  entries, an unprotected DACL or access masks outside the policy no longer
  opens.

### Unchanged

- `ValidateCertificate`, `ValidateOptions`, `ErrInvalidCertificate`,
  `ErrCallerIdentity` and the native adapters keep their API. The adapters keep
  their behavior, except that `CNGKeys.Open` follows cng v0.5's exact policy
  check (see above).
- The `lifecycle` package has no API or behavior change.

### Continuous integration

- A GitHub Actions workflow builds, vets (amd64 and 386) and tests the module
  on Windows, and checks formatting, builds, vets and tests it on Linux. Tests
  that need an elevated token or `KEPPIN_STORE_LIVE=1` skip themselves.

See [Upgrading from v0.3.0](README.md#14-upgrading-from-v030).

## Compatibility

- Go 1.26.8
- golang.org/x/sys v0.48.0
- github.com/keppin-oss/cng v0.5.1
- Windows/amd64. Enrollment needs a domain member running the broker as
  LocalSystem and a template that accepts an ECDSA P-256 key.

## Validation

- Offline: the test suite passed on Windows with an elevated token and
  `KEPPIN_STORE_LIVE=1`, with no test skipped, including the crash matrix of
  the state machine on the real NTFS journal. The CI workflow adds build and
  vet on Windows (vet also for 386) and Linux, and the Linux test run.
- Live, against an AD CS Enterprise CA, on Windows 11 Pro (build 26200) and
  Windows Server 2025 Standard (build 26100), domain members, with one signed
  build, Microsoft Defender Antivirus, attack surface reduction rules in audit
  and then block mode, Sysmon and CA auditing:
  - issued, denied and pending requests, and a CA service suspended during the
    submit;
  - the CA recorded the computer account as requester and a request equal to
    the CSR;
  - in the denied and suspended-submit cases the key was deleted with cng
    v0.5.1's verified delete;
  - key export was refused, and only the target service could use the key;
  - no child process, and no `certreq.exe`; network connections only to the
    CA;
  - no Defender or ASR event for the module's process.
- The live runs validated the same production logic before the public
  module-path rewrite.
- Not validated: other Windows builds or editions, other key storage
  providers, Defender for Endpoint, WDAC or AppLocker policies, power loss
  during a journal write, the elevated tests under the race detector.

## Known limitations

- A CA call that does not return cannot be cancelled in process. When its
  context ends, `Step` returns an error matching `lifecycle.ErrQuiescence` and
  the attempt stays open; for a submit, the attempt ends `CA_UNKNOWN` only at
  the `Step` after an administrator records the operation resolution, and it
  then needs an attempt resolution.
- No administrative tooling is included for resolutions or journal archiving.
- Opening the key for TLS serving, activation, rotation and renewal are
  consumer responsibilities. The technical reference describes how to open the
  key of an `ACCEPTED` attempt with cng.
