# Keppin-OSS Enterprise TLS — Technical Reference

This document describes v0.4.0.

## 1. Purpose and scope

`Keppin-OSS Enterprise TLS` (Go package `enterprise`) provisions a machine-scoped
localhost certificate from an Active Directory Certificate Services (AD CS)
Enterprise CA on Windows and independently validates it before reporting
success.

Enrollment runs **in process, with no child process**:
- a CNG key created by `github.com/keppin-oss/cng`;
- a PKCS #10 request built in Go;
- the CA called through the in-process `ICertRequest` COM interface;
- the whole attempt driven by the durable state machine `lifecycle.Enrollment`,
  which recovers from crashes through a protected journal.

The `certreq.exe` workflow of earlier versions (`Provider.Enroll`) was removed
in v0.4.0 (see [Upgrading from v0.3.0](#14-upgrading-from-v030)).

The module is deliberately narrow. It owns Enterprise CA enrollment and the
validation, installation and cleanup that follow from it. An `ACCEPTED`
attempt means **installed in `LocalMachine\My` with a proven binding to its
key**, not "in use". The module does not own:
- local-CA creation or a local-TLS fallback;
- opening the key for TLS serving, activation, rotation or renewal;
- general certificate management.

Those responsibilities belong to the consumer.

## 2. Supported platform

The supported target is **Windows/amd64**.

- Live enrollment, installation and cleanup are Windows-only.
- Live validation of v0.4.0 was run on Windows 11 Pro (build 26200) and
  Windows Server 2025 Standard (build 26100), as domain members, against an
  AD CS Enterprise CA (see [Validation and testing](#17-validation-and-testing)).
- `Windows/386` is not supported; `Windows/ARM64` is not verified.
- On other platforms the package compiles: Windows-only seams return errors,
  they are not no-ops (see [Platform behavior and build tags](#16-platform-behavior-and-build-tags)).

## 3. Architecture and ownership boundary

```
lifecycle.Enrollment (durable journal, Start/Step)
 ├─ KeyStore   = enterprise.CNGKeys          create the key with the service's DACL
 ├─ Requester  = enterprise.NativeRequester  CSR in Go, ICertRequest in process
 ├─ CertStore  = enterprise.MachineMy        install in LocalMachine\My, binding check
 ├─ Deleter    = enterprise.AttemptDeleter   terminal cleanup of files and key
 └─ Validate   = enterprise.EnrollmentValidator.Validate
```

`Start` records a new attempt; `Step` performs at most one transition. The
normal path and crash recovery are the same code, selected by the last durable
record. The attempt moves through `PREPARE` → `KEY_READY` → `SUBMITTED` →
`ISSUED` → `DONE`, with the phases `create`, `submit`, `retrieve` and `install`.
Before each non-repeatable effect a launch record is written; after a crash the
launch record is reconciled and the effect is **never repeated**:
- a key is adopted only from a recorded create result, never by opening a key
  that already exists;
- a submit whose result was lost is never resubmitted: the attempt ends
  `CA_UNKNOWN`;
- an install is never repeated: only the binding check on the certificate
  re-read from `My` proves it.

Ownership boundaries:
- **Key identity** is fixed per attempt: the caller chooses a new container
  name in `lifecycle.Params`, and the record's `TargetSID` and `Profile`, not
  the current configuration, drive every step.
- **Caller identity.** `NativeRequester` calls the CA only when the calling
  thread has no impersonation token and the process runs as the expected SID
  (`S-1-5-18`, LocalSystem, in the example). Any other identity is refused with
  `ErrCallerIdentity` before the CA call.
- **Cleanup** is driven by a terminal cleanup plan per attempt, with a
  per-artifact result; nothing outside the plan is deleted.

## 4. Requirements

Native enrollment requires:
- a domain-joined Windows machine that can reach the AD CS Enterprise CA;
- a broker process running as **LocalSystem**. It authenticates to the CA as
  the **computer account** (`DOMAIN\HOST$`), so the computer account (for
  example through Domain Computers) needs **Read and Enroll** on the template;
- a certificate template that accepts an **ECDSA P-256** key from the
  Microsoft Software Key Storage Provider and issues the localhost Server
  Authentication certificate. A template whose key settings do not accept a
  P-256 key denies the request, and the state machine reports `DENIED`. The
  HRESULT depends on the template: in the live validation an RSA-only template
  answered `CERTSRV_E_KEY_LENGTH` (`0x80094811`, the public key does not meet
  the template's minimum size), while missing Enroll permission gives
  `CERTSRV_E_TEMPLATE_DENIED` (`0x80094012`);
- a journal directory that only SYSTEM and Administrators can access. The
  module refuses any other directory;
- the Windows service whose service SID will use the key: `NewCNGKeys(service)`
  gives that SID access to the key.

Module-level dependencies (see `go.mod`):
- Go `1.26.8`;
- `github.com/keppin-oss/cng v0.5.1` (Windows CNG key creation, opening and
  verified deletion, with an explicit key policy);
- `golang.org/x/sys v0.48.0`.

## 5. Installation / import

```go
import (
    enterprise "github.com/keppin-oss/enterprise-tls"
    "github.com/keppin-oss/enterprise-tls/lifecycle"
)
```

The package names are `enterprise` and `lifecycle`.

## 6. Native enrollment

[`examples/native-enroll`](../examples/native-enroll/main.go) shows the
complete wiring. In short:

```go
journal, _ := lifecycle.OpenJournal(dir)          // protected directory
store, _ := lifecycle.OpenAttemptStore(dir)
keys, _ := enterprise.NewCNGKeys("MyService")
validator := enterprise.EnrollmentValidator{Roots: roots, Intermediates: inter,
    Issuer: issuer, Templates: map[string]asn1.ObjectIdentifier{template: oid}}
e := lifecycle.Enrollment{
    Journal:  journal,
    Guard:    lifecycle.ProcessGuard{Journal: journal},
    Deleter:  enterprise.NewAttemptDeleter(store, keys),
    Requests: enterprise.NewNativeRequester(store, "S-1-5-18"),
    Keys:     keys,
    Stores:   enterprise.NewMachineMy(),
    Validate: validator.Validate,
    Pace:     lifecycle.PacePolicy{MinInterval: time.Minute, RetrieveMax: 3},
}
a, err := e.Start(ctx, lifecycle.Params{CA: ca, Template: template,
    Provider: "Microsoft Software Key Storage Provider", Container: name,
    TargetSID: keys.TargetSID(), Profile: "service-sid"})
if err != nil {
    return err // for example ErrAttemptOpen, ErrAttemptBlocked or ErrPaced: no new attempt
}
for {
    _, err := e.Step(ctx)
    switch {
    case errors.Is(err, lifecycle.ErrNoOpenAttempt):
        got, plan, err := e.Report(ctx, a.ID) // the attempt is closed
        if err != nil {
            return err
        }
        return handle(got, plan) // got.Outcome == lifecycle.Accepted is the only success
    case errors.Is(err, lifecycle.ErrRetrieveNotDue):
        time.Sleep(time.Minute)
    case errors.Is(err, lifecycle.ErrCleanupIncomplete):
        // recorded in the closed plan; the next Step returns ErrNoOpenAttempt
    case err != nil:
        return err
    }
}
```

`PacePolicy.MinInterval` is the minimum time between two new attempts; a
`Start` that comes earlier is refused before an attempt or a CA request exists.

### Outcomes

| Outcome | Meaning | Blocks new attempts |
| --- | --- | --- |
| `ACCEPTED` | issued, validated, installed in `LocalMachine\My`, binding proven | no |
| `DENIED` | the CA denied the request; the key is deleted, the CSR kept | no |
| `BLOCKED_PKI` | the request is pending at the CA; key and CSR kept, RequestId recorded | yes |
| `CA_UNKNOWN` | the CA outcome of a submit cannot be proven (lost result, failed HRESULT, call that did not return) | yes |
| `INCONCLUSIVE` | the evidence does not prove a result (for example validation or binding check failed) | yes |
| `ABANDONED_UNVERIFIED` | a create result was lost; the key, which cannot be attributed, is kept | no |
| `ABORTED_PRE_SUBMIT` | the attempt was aborted before any submit | no |

Only `ACCEPTED` is a success. A blocking outcome is released only by
`lifecycle.Resolver.ResolveAttempt` with an `AttemptResolution`: the actor, a
decision, the attempt's RequestId (0 only when it never learned one), a reason
and evidence (a CA record or ticket). The decisions are:
- `CA_DENIED`, `CA_ISSUED_NOT_INSTALLED`, `CA_REQUEST_REMOVED`: what the CA
  shows for that RequestId;
- `ARTIFACTS_SETTLED` (`INCONCLUSIVE` only);
- `RISK_ACCEPTED` (`CA_UNKNOWN` only): an explicit acceptance of the risk of a
  new submit without a proven CA outcome. It is the only decision for a
  `CA_UNKNOWN` attempt without a RequestId.

A resolution never reopens the attempt and performs no effect; it only lets
`Start` create a new attempt. Missing CA rows are never treated as a CA
decision.

### Report

`Enrollment.Report` returns the attempt and its cleanup plan: attempt ID, CA,
RequestId, CSR hash, key SPKI, outcome, reason, and the result of every planned
artifact. For `ACCEPTED` there is no plan: the key and certificate stay.

### Using the enrolled key

This module does not open the key for serving. A consumer that serves TLS opens
it from the report of an `ACCEPTED` attempt, without searching by subject, CN,
template or CA:
- the key container is `Attempt.Container` in the Microsoft Software KSP; open
  it with `windowscng.Open(container, policy)` from
  `github.com/keppin-oss/cng/windowscng`, where `policy` comes from
  `windowscng.NewServicePolicy` for the service that will use the key;
- the certificate is the one in `LocalMachine\My` whose SHA-256 is
  `Attempt.CertHash`;
- before serving, the consumer checks that the opened key's public key matches
  `Attempt.SPKI` (SHA-256 of the SubjectPublicKeyInfo).

Choosing which `ACCEPTED` certificate to serve, activation, rotation and
renewal are consumer decisions.

## 7. Public API

Native path (package `enterprise`):

| Function or type | Role |
| --- | --- |
| `NewCNGKeys(service) (*CNGKeys, error)` | `lifecycle.KeyStore` and key `Deleter`; ECDSA P-256 machine key with the service SID's access policy (cng v0.5.1); verified delete |
| `NewNativeRequester(store, expectSID) *NativeRequester` | `lifecycle.Requester`; CSR in Go, `ICertRequest` in process |
| `NewMachineMy() MachineMy` | `lifecycle.CertStore`; install and `VerifyBinding` in `LocalMachine\My` |
| `NewAttemptDeleter(store, keys) AttemptDeleter` | cleanup of the attempt's files and key |
| `EnrollmentValidator` | full validation of the issued certificate |
| `ErrCallerIdentity` | the CA call was refused: caller identity not established |

The `lifecycle` package holds the state machine (`Enrollment`, `Params`,
`Attempt`, `Outcome`, `PacePolicy`), the journal (`OpenJournal`,
`OpenAttemptStore`, `FileJournal`, compaction), the resolution API
(`Resolver`, `AttemptResolution`), the process guard (`ProcessGuard`,
`Quiescer`), consumer-side activation fencing (`Activator`) and terminal
cleanup (`Cleaner`).

Also supported: `ValidateCertificate(data, opts)` validates certificate
material against the localhost policy and reports failures matching
`ErrInvalidCertificate` (see [Certificate validation](#9-certificate-validation)).

## 8. EnrollmentValidator

`EnrollmentValidator.Validate` checks the issued certificate against the
attempt before it is installed:
- the chain verifies to `Roots`, through `Intermediates`, and the leaf's direct
  issuer is `Issuer` (both `Roots` and `Issuer` are required);
- the localhost policy of [Certificate validation](#9-certificate-validation);
- the certificate's public key is the attempt's key (`Attempt.SPKI`);
- the template extension names the attempt's template (`Templates` maps the
  template name to the OID of its v2 extension).

A failure ends the attempt `INCONCLUSIVE` with the reason
`certificate validation failed: …`.

## 9. Certificate validation

`ValidateCertificate` (and `EnrollmentValidator`) perform, at minimum:
- parse of PEM, DER, or base64 X.509 material;
- validity-period check against `ValidateOptions.Now` (default `time.Now`);
- localhost SAN policy (below);
- Server Authentication EKU and `digitalSignature` key usage;
- public-key match against the enrollment key (for `ValidateCertificate`, when
  `ValidateOptions.ExpectedPublicKey` is set);
- chain verification via `crypto/x509` against the caller's roots (or
  `x509.SystemCertPool` for `ValidateCertificate` without roots), plus
  intermediates.

**SAN policy.** The check operates on the SAN fields exposed by the Go X.509
parser: DNS names, IP addresses, URIs, and email addresses. It requires one DNS
SAN `localhost` and two IP SANs `127.0.0.1` and `::1`, and rejects additional
DNS names, IP addresses, URIs, email addresses, and wildcards. Other
`GeneralName` forms that the parser does not expose are not inspected.

## 10. Journal and process guard

`lifecycle.OpenJournal(dir)` opens a checksummed journal in a directory that
only SYSTEM and Administrators can access, holding an exclusive lease: a second
process that opens the same journal fails. Schema 1 journals written by earlier
development builds are refused, not migrated.

`ProcessGuard` is a durable crash latch. An operation that did not finish
blocks later operations (`lifecycle.ErrInterrupted`) until it is reconciled:
by a qualified `Quiescer`, or by an administrator's statement recorded with
`Resolver.ResolveOperation`. `FileJournal.Compact`
rewrites the journal and, with `CompactOptions.Retention`, archives and purges
closed cleanup plans (a value of 90 days from complete terminal closure is
recommended).

A CA call that does not return cannot be cancelled in process. When its
context ends, `Step` returns an error matching `lifecycle.ErrQuiescence` and
the launch record stays. After a restart the latch holds (`ErrInterrupted`)
and no submit is sent; once an administrator records the operation resolution,
the next `Step` ends the attempt `CA_UNKNOWN`.

## 11. Cleanup and lifecycle

Every non-`ACCEPTED` outcome closes with a terminal cleanup
plan. Each planned artifact (key, CSR, CA output files) has a retention rule
per outcome and a recorded result (`DELETED`, `RETAINED`,
`NOT_FOUND_UNVERIFIED`, `SKIPPED_NOT_OWNED` or `FAILED`). Keys are deleted
with `windowscng.Delete` from cng v0.5.1, which checks the key policy and the
public key recorded in the journal on the handle it deletes. Artifacts whose identity cannot be established are recorded as
unidentified and never deleted.

## 12. Windows / CNG integration

- Native keys are machine-scoped ECDSA P-256 keys in the Microsoft Software Key
  Storage Provider, created create-only by `windowscng.Create` with an
  access policy for the target service SID; export is not allowed.
- The CA is called through `ICertRequest` on a dedicated, locked OS thread in
  the multithreaded apartment.
- Certificates are installed in `LocalMachine\My`
  (`CERT_SYSTEM_STORE_LOCAL_MACHINE`) and bound to the attempt's key;
  `MachineMy.VerifyBinding` re-reads the store and proves the binding, with no
  repair.

## 13. Trust model and caller responsibilities

Callers must:
- run the native broker as LocalSystem with a protected journal directory;
- provide trusted CA, template, roots and issuer configuration;
- treat `AttemptResolution` as privileged administrative input and protect
  its provenance;
- classify outcomes through `Outcome` and `errors.Is`/`errors.As`,
  never through text;
- not delete a key whose ownership is unproven.

## 14. Upgrading from v0.3.0

- The `certreq.exe` path is removed: `Provider`, `New`, `Provider.Enroll`,
  `NewWithProcessJournal`, `Config`, `Result`, `Status`, `KeyState`,
  `CleanupInfo`, `Uninstall`, `BuildRequestINF` and the sentinels
  `ErrNotConfigured`, `ErrUnavailable`, `ErrEnrollmentFailed`,
  `ErrEnrollmentIncomplete`, `ErrEnrollmentPending`, `ErrProcessQuiescence`,
  `ErrOperationBlocked`, `ErrCleanupFailed`, `ErrOwnershipMismatch` no longer
  exist. Callers move to [Native enrollment](#6-native-enrollment).
- Keys and certificates enrolled by the old path are not handled by this
  module; remove them with the administrative tooling of the host.
- `github.com/keppin-oss/cng` moves from v0.4.0 to v0.5.1. A consumer that opens
  the enrolled key calls `windowscng.Open(container, policy)` instead of
  `OpenForService`. cng v0.5 checks the policy exactly: a key with extra access
  entries, an unprotected DACL or access masks outside the policy no longer
  opens.
- The API of `ErrInvalidCertificate`, `ErrCallerIdentity`, the native
  adapters and the `lifecycle` package is unchanged. The behavior of the
  adapters is unchanged except for the exact policy check above: `CNGKeys.Open`
  can refuse a key whose DACL an earlier cng version tolerated.

## 15. Upgrading from v0.2.0

Upgrade to v0.3.0 first; see the
[v0.3.0 release notes](release-notes-v0.3.0.md). The native path uses an
**ECDSA P-256** key: the template must accept it.

## 16. Platform behavior and build tags

Live enrollment and cleanup are Windows-only. On non-Windows platforms the
package compiles because Windows seams have stubs (build tag `!windows`) that
return errors. There are no other build tags.

## 17. Validation and testing

Ordinary (non-live) verification:

```powershell
go build ./...
go vet ./...
go test ./...
```

The ordinary tests use fakes for the CA, the key store, the certificate store
and the journal faults. A few tests need an elevated token (protected NTFS
journal and attempt directory) or `KEPPIN_STORE_LIVE=1` (a per-user store
binding test) and are skipped otherwise. The GitHub Actions workflow runs
this verification on Windows (amd64 and 386 vet) and Linux (with `gofmt`).

Validation of v0.4.0 before release:
- the full suite with an elevated token and `KEPPIN_STORE_LIVE=1`, including
  the crash matrix of the state machine on the real NTFS journal: every test
  passed, none skipped;
- live runs on Windows 11 Pro (build 26200) and Windows Server 2025 Standard
  (build 26100), domain members, against an AD CS Enterprise CA, with one
  signed build, Microsoft Defender Antivirus, attack surface reduction rules in
  audit and then in block mode, Sysmon and CA auditing:
  - issued: `ACCEPTED`, `RawRequest` at the CA equal to the CSR, the requester
    is the computer account, key export refused, only the target service can
    use the key, no child process, network connections only to the CA;
  - denied: `DENIED`, key deleted with cng v0.5.1's verified delete, CSR kept;
  - pending: `BLOCKED_PKI`, `Start` refused until the resolution;
  - CA service suspended during the submit: the call blocked, the journal lease
    held, after a restart no resubmit and `CA_UNKNOWN`, key deleted;
  - with the ASR rules in block mode: `ACCEPTED`, no Defender or ASR event for
    the module's process.

The live runs validated the same production logic before the public
module-path rewrite.

Not validated: other Windows builds or editions, other key storage providers,
Defender for Endpoint, WDAC or AppLocker policies, power loss during a journal
write, the elevated tests under the race detector, very large CA responses
through the real `certcli`.

## 18. Limitations

- Live enrollment requires Windows/amd64, a domain member, LocalSystem and a
  reachable AD CS Enterprise CA.
- A CA call that does not return cannot be cancelled in process. When its
  context ends, `Step` returns an error matching `lifecycle.ErrQuiescence` and
  the attempt stays open; for a submit, the attempt ends `CA_UNKNOWN` only at
  the `Step` after an administrator records the operation resolution, and it
  then needs an attempt resolution.
- No administrative tooling is included for `Resolver` decisions or for
  journal archiving; callers build it on the `lifecycle` API.
- `ACCEPTED` is not "in use": serving, activation, rotation and renewal belong
  to the consumer.
- The module provisions only the `localhost` identity and validates the SAN
  fields exposed by the Go parser.
- No API stability guarantee is made before v1.

## 19. Troubleshooting

1. **Outcome and reason** — read `Enrollment.Report`: the outcome, its reason
   and the cleanup plan.
2. **Identity** — is the broker LocalSystem with no impersonation token
   (`ErrCallerIdentity`)? Does the computer account have Read and Enroll on the
   template?
3. **Template** — does it accept an ECDSA P-256 key from the Microsoft Software
   KSP? `DENIED` with `CERTSRV_E_KEY_LENGTH` (`0x80094811`) points to the key
   settings of the template; `CERTSRV_E_TEMPLATE_DENIED` (`0x80094012`) points
   to its permissions.
4. **Journal** — is the directory accessible only to SYSTEM and Administrators?
   Is another process holding the journal?
5. **Blocked attempts** — `BLOCKED_PKI`, `CA_UNKNOWN` and `INCONCLUSIVE` need
   an `AttemptResolution`; check the CA for the recorded RequestId.

## 20. License

Apache License 2.0. See [LICENSE](../LICENSE).
