# Keppin-OSS Enterprise TLS — Technical Reference

## 1. Purpose and scope

`Keppin-OSS Enterprise TLS` (Go package `enterprise`) provisions a localhost
certificate from an Active Directory Certificate Services (AD CS) Enterprise CA
on Windows, using the native `certreq.exe` workflow, and independently validates
the returned certificate before reporting success.

The module is deliberately narrow. It owns Enterprise CA enrollment and the
validation and cleanup that follow from it. It does not own local-CA creation, a
local-TLS fallback, TLS serving/runtime configuration, or general certificate
management. Those responsibilities are external to this module.

## 2. Supported platform

The supported and verified target is **Windows/amd64**.

- Some files use the `windows` build tag. This expresses that the implementation
  is Windows-specific; it is not a guarantee for every Windows architecture.
- `Windows/386` is not supported.
- `Windows/ARM64` is not verified.
- The native layout used by this module has been validated only on amd64.
- On non-Windows platforms, only the certificate-store and key-remover seams
  are stubbed, and those stubs return an `errNotWindows` error; they are not
  no-ops. This is not a promise that every `Enroll` call fails immediately with
  `errNotWindows`: with a configured CA it may still attempt to run the
  `certreq.exe` runner (see
  [Platform behavior and build tags](#15-platform-behavior-and-build-tags)).

## 3. Architecture and ownership boundary

The primary entry point is `Provider.Enroll`, which orchestrates the native
workflow:

1. generate the machine-scoped key and PKCS#10 request with `certreq -new`;
2. submit the request to the Enterprise CA with `certreq -submit`;
3. independently validate the returned leaf, chain, and key binding;
4. install the certificate with `certreq -accept`;
5. capture cleanup metadata for later removal.

Two ownership boundaries are explicit:

- **Key identity** is fixed per attempt: a randomly generated, module-namespaced
  key container name is allocated *before* `certreq -new`, so the key identity
  is known even if enrollment fails later.
- **Cleanup metadata** is treated as privileged input: `Uninstall` trusts the
  values it is given, so its provenance and integrity are the caller's
  responsibility (see [Cleanup and lifecycle](#12-cleanup-and-lifecycle)).

## 4. Requirements

Live enrollment requires:

- Windows (amd64), with the machine able to reach an AD CS Enterprise CA;
- the `certreq.exe` executable, resolvable through the process PATH;
- machine/computer enrollment permissions and a suitable certificate template on
  the CA;
- Administrator elevation for machine-scoped key and certificate-store
  operations.

Module-level dependencies (see `go.mod`):

- Go `1.26.5`;
- `github.com/keppin-oss/cng v0.1.1` (Windows CNG key primitives);
- `golang.org/x/sys v0.28.0`.

## 5. Installation / import

```go
import enterprise "github.com/keppin-oss/enterprise-tls"
```

The package name is `enterprise`.

## 6. Configuration and trust boundary

```go
type Config struct {
    CA       string // certreq.exe "-config" form: "CAHostName\CAName"
    Template string // optional; the template directive is omitted when empty
}
```

`CA` is required by the current implementation; an empty `CA` yields
`StatusNotConfigured` / `ErrNotConfigured`.

`Template` is interpolated into the generated request INF, and the generated key
container name is also interpolated into the INF. These values are not fully
escaped for INF syntax. They must come from trusted administrative configuration
and must not contain newlines, control characters, or additional INF syntax.
They must not be populated directly from untrusted user or remote input.

`certreq.exe` is resolved through the calling process's PATH/environment, which
must therefore be trusted.

## 7. Public API

```go
func New(cfg Config) *Provider
func (p *Provider) Enroll(ctx context.Context) (*Result, error)

func ValidateCertificate(data []byte, opts ValidateOptions) (*x509.Certificate, error)
func BuildRequestINF(cfg Config, keyContainer string) string

func Uninstall(info CleanupInfo) error
```

`New` configures the real native provider (the real `certreq.exe` runner, the
native Windows machine certificate store, and the native CNG key provider).

`Enroll` returns `(*Result, nil)` on success. On a structured failure it may
return the same `*Result` as both the value and the error; use `errors.Is` for
sentinel errors and `errors.As` to extract the `*Result` type.

`BuildRequestINF` renders the `certreq.exe` request (`.inf`) content. It is
exported for inspection and testability; the supported consumer flow is
`New` → `Enroll`.

`ValidateCertificate` independently validates certificate material against the
localhost policy (see [Certificate validation](#10-certificate-validation)).

`Uninstall` removes the leaf certificate and private key described by a
`CleanupInfo` (see [Cleanup and lifecycle](#12-cleanup-and-lifecycle)).

`ValidateOptions` selects the trust roots, intermediates, reference clock, and
expected public key used by `ValidateCertificate`. `Status.String()` and
`KeyState.String()` return human-readable labels for logging/diagnostics; they
are not the canonical classification API.

## 8. Result, status, and key state

`Status` is the canonical classification; `Err` carries a wrapped sentinel error.

| Status | Meaning |
| --- | --- |
| `StatusUnknown` | zero value; no attempt was made |
| `StatusNotConfigured` | required CA configuration is missing |
| `StatusUnavailable` | `certreq.exe` missing, or the Enterprise CA unreachable |
| `StatusEnrollmentFailed` | enrollment failed (local errors or a tool/CA rejection) |
| `StatusInvalidCertificate` | material returned but failed independent validation |
| `StatusSuccess` | enrolled and independently validated |
| `StatusEnrollmentIncomplete` | valid certificate installed but cleanup metadata could not be captured |

`StatusEnrollmentFailed` covers both local errors that occur before or around
the tool run (for example file or request handling) and CA rejections or
`certreq.exe` failures.

Sentinel errors (use with `errors.Is`):

- `ErrNotConfigured`
- `ErrUnavailable`
- `ErrEnrollmentFailed`
- `ErrInvalidCertificate`
- `ErrEnrollmentIncomplete`
- `ErrCleanupFailed`
- `ErrOwnershipMismatch`

`Tool`, `ExitCode`, and `Stderr` are diagnostics for humans and logs. Policy
decisions must use `Status` and `errors.Is`/`errors.As`, never string matching on
tool output.

`KeyState` classifies what is known about the key container generated for an
attempt:

| KeyState | Meaning |
| --- | --- |
| `KeyStateNone` | zero/unclassified state (also the zero value on success); do not infer absence of a key |
| `KeyStateRemoved` | owned key was created and removed |
| `KeyStatePresent` | owned key may remain; retry via `Result.KeyContainer` |
| `KeyStateUnproven` | ownership unproven; the caller must not delete the key |

A successful enrollment may report `KeyStateNone` (the zero value), because the
certificate and key are intended to remain installed.

## 9. Request and enrollment flow

The request INF requests a machine-scoped private key in the Microsoft Software
Key Storage Provider with `Exportable = FALSE`, and requests a 2048-bit RSA key
with `KeyUsage = 0xA0` (digitalSignature | keyEncipherment) and
`HashAlgorithm = sha256`. The `[Extensions]` section requests one DNS SAN
(`localhost`) and two IP SANs (`127.0.0.1` and `::1`) plus the Server
Authentication EKU (`1.3.6.1.5.5.7.3.1`).

These are the properties the module requests from `certreq.exe`; the INF requires
`MachineKeySet = TRUE` and `Exportable = FALSE`. The actual issued certificate is
subject to the Enterprise CA template and policy and is independently validated
before success is reported. The module does not subsequently verify either the
resulting key export policy or the actual machine-scope ownership of the key,
and never writes private-key material as PEM or PFX. The CA does not
retroactively change the local private key.

The `-machine` flag governs the request/key context; it does not by itself prove
the identity under which the CA authenticates the submission.

The returned chain (a PKCS#7/CMS file produced by `certreq.exe`) supplies
intermediates for trust verification when present. It is optional: a read error
or absence is handled as an absent optional chain in the current flow.

## 10. Certificate validation

`ValidateCertificate` performs, at minimum:

- parse of PEM, DER, or base64 X.509 material;
- validity-period check against `ValidateOptions.Now` (default `time.Now`);
- localhost SAN policy (below);
- Server Authentication EKU and `digitalSignature` key usage;
- public-key match against `ValidateOptions.ExpectedPublicKey` when set (the
  enrollment key);
- chain/trust verification via `crypto/x509` against the platform/system trust
  available to the calling process (`x509.SystemCertPool` by default, or
  caller-provided `ValidateOptions.Roots`), plus the returned intermediates.

**SAN policy.** The check operates on the SAN fields exposed by the Go X.509
parser: DNS names, IP addresses, URIs, and email addresses. It requires one DNS
SAN `localhost` and two IP SANs `127.0.0.1` and `::1`, and rejects additional
DNS names, IP addresses, URIs, email addresses, and wildcards. Other `GeneralName`
forms that the parser does not expose are not inspected by this check.

**Trust context.** The module uses `x509.SystemCertPool` and
`Certificate.Verify`. On Windows the result depends on the trust made available
to the calling process; it is not a guarantee that verification is limited
exclusively to machine roots. When a caller must control the trust set, it can
supply explicit roots via `ValidateOptions.Roots`.

**Chain file parsing.** The PKCS#7/CMS chain file is parsed by a minimal
certificate extractor, not a complete CMS validator. Extracted intermediates are
added to the intermediate pool for the subsequent X.509 verification; they are
not promoted to trust roots. Trust is established by that subsequent X.509
verification, not by the parser.

## 11. Status and error classification

`certreq.exe` failures are classified conservatively and fail closed:

- `certreq.exe` missing (`exec.ErrNotFound`), in any phase → `StatusUnavailable`;
- CA reachability HRESULTs (`0x800706BA`, `0x800706D9`, `0x80072EE7`) in the
  `-submit` phase only → `StatusUnavailable`;
- every other non-zero outcome (rejection, template/policy denial, auth failure,
  malformed request, a failed `-new`, a failed `-accept`, or any ambiguous
  failure) → `StatusEnrollmentFailed`.

Incomplete enrollment is observable rather than collapsed into a generic
failure: `StatusEnrollmentIncomplete` carries best-effort retry metadata, and
key-removal failures remain visible via `Result.KeyCleanupErr`.

## 12. Cleanup and lifecycle

`Uninstall(info CleanupInfo)` removes the leaf certificate and private key
described by `info`. It deletes only the artifacts this module manages; it is
best-effort and **not transactional**, and it does not roll back every side
effect of `certreq.exe`.

**`CleanupInfo` is privileged input.** Its provenance and integrity must be
protected by the caller. The behavior depends on the state of the certificate:

- When the certificate is found, the module verifies the persisted identity and
  key association against the installed certificate before deleting.
- When the certificate is not found, the provider and container name from the
  metadata are used to attempt key deletion; ownership of the absent
  certificate's key is not independently reconstructed here.

Fabricated, substituted, or stale metadata can therefore direct a privileged
deletion. The uninstall example treats its JSON file as trusted administrative
input, not as data a caller can safely pass through without integrity
protection.

Partial failure (for example in `-accept`, metadata capture, or the filesystem)
can leave artifacts behind. Removal of temporary files is best-effort. The
module does not manage every artifact that may appear in the request store, and
recovery or retry may require administrative reconciliation. Not every
incomplete enrollment is guaranteed to be removable via `Uninstall`.

`ErrCleanupFailed` wraps cleanup failures that are not ownership mismatches.
`ErrOwnershipMismatch` indicates that ownership could not be established, either
because persisted metadata disagrees with a present artifact or because the
certificate is absent and required key metadata is missing. No artifact is
deleted on these paths.

## 13. Windows / CNG integration

Machine-scope operations use the `LocalMachine\My` certificate store
(`CERT_SYSTEM_STORE_LOCAL_MACHINE`). CNG key deletion is delegated to the shared
Keppin-OSS CNG primitive (`github.com/keppin-oss/cng/windowscng`), which performs
the Microsoft Software KSP machine-scoped deletion. Keppin-OSS CNG is used here
for container deletion, not for creating or validating the enrollment key.

## 14. Trust model and caller responsibilities

The request and validation enforce the expected `localhost` identity, and
returned material is validated before success is reported.

Callers must:

- provide trusted CA and (optionally) template configuration (see
  [Configuration and trust boundary](#6-configuration-and-trust-boundary));
- run with Administrator elevation for machine-scoped operations;
- protect the provenance and integrity of `CleanupInfo` used for `Uninstall`;
- classify outcomes through `Status` and `errors.Is`/`errors.As`, never through
  tool output;
- not delete a key whose ownership is `KeyStateUnproven`.

## 15. Platform behavior and build tags

Live enrollment and cleanup are Windows-only. On non-Windows platforms the
package still compiles because the Windows certificate-store and key-removal
seams have stubs (see `cleanup_other.go`, build tag `!windows`); those stubs
return an `errNotWindows` error rather than succeeding. The Windows
implementation lives in `cleanup_win.go` (build tag `windows`).

The smoke test in `enroll_smoke_test.go` uses the build tag
`windows && enterprise_tls_smoke` and is not part of the ordinary test suite.

## 16. Examples

Complete, compilable examples live under [`../examples/`](../examples/):

- [`../examples/enroll`](../examples/enroll) — the enrollment flow. It is
  demonstrative: on success (and when `CLEANUP_FILE` is set) it persists
  `CleanupInfo`, but on a failure path it prints diagnostics and does not persist
  `Result.Cleanup`; retaining recovery metadata is a consumer responsibility.
- [`../examples/classification`](../examples/classification) — synthetic
  classification of structured statuses and sentinel errors via the public API.
- [`../examples/uninstall`](../examples/uninstall) — the cleanup boundary
  consuming a previously persisted `CleanupInfo`, treated as trusted
  administrative input.
- [`../examples/validate`](../examples/validate) — synthetic strict localhost
  validation using in-memory fixtures.

## 17. Validation and testing

Ordinary (non-live) verification:

```powershell
go build ./...
go vet ./...
go test -buildvcs=false ./...
```

Unit tests inject a fake command runner, a fake certificate store, a fake key
remover, and a test trust root; they do not invoke a real Enterprise CA or
mutate the host trust store or machine certificate store.

A manual smoke test (`-tags enterprise_tls_smoke`) exercises the real `Enroll`
orchestration against real `certreq.exe` without a real Enterprise CA. It must be
run elevated on Windows and is not part of the ordinary test suite. The smoke
test includes its own safety net for cleanup, which is test-specific and not the
cleanup contract for consumers. In particular, the safety net's treatment of a
`KeyStateUnproven` outcome — it deletes the recorded key container on the test
path even where the module's own rule forbids consumer deletion of an unproven
key — is a test-specific accommodation and remains a known, non-blocking backlog
item; it is not a consumer contract.

## 18. Limitations

- Live enrollment requires Windows/amd64 and a reachable AD CS Enterprise CA.
- The module provisions only the expected `localhost` identity and validates the
  SAN fields exposed by the Go parser, not every possible `GeneralName` form.
- The issued certificate is subject to the Enterprise CA template and policy; the
  module validates what is returned rather than guaranteeing issuance or key
  export policy.
- The INF is built from configuration assumed to be trusted; it is not hardened
  against hostile input.
- Cleanup is best-effort and not transactional; it does not roll back every side
  effect of `certreq.exe`.
- The PKCS#7/CMS chain parser is a minimal certificate extractor, not a complete
  CMS validator.
- The module does not provide fallback, provider-selection, or orchestration
  policy.
- No API stability or forward-compatibility guarantee is made.

## 19. Troubleshooting

Diagnose in this order:

1. **Configuration** — is `CA` set in `certreq.exe -config` form
   (`CAHostName\CAName`)? Is `Template` correct (or intentionally empty)?
2. **Platform** — live enrollment is Windows-only (amd64); is the process
   elevated?
3. **`certreq.exe`** — is it present and resolvable through the process PATH?
4. **CA/template permissions** — does the machine account have enrollment
   permission and does the template issue the required certificate?
5. **Structured `Status`** and **sentinel error** via `errors.Is`.
6. **Tool diagnostics** — `Result.Tool`, `Result.ExitCode`, `Result.Stderr`
   (for humans/logs only).
7. **Key state and cleanup metadata** — `Result.KeyState`,
   `Result.KeyCleanupErr`, `Result.KeyContainer`, `Result.Cleanup`.

## 20. License

Apache License 2.0. See [LICENSE](../LICENSE).
