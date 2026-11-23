# Keppin-OSS Enterprise TLS

`Keppin-OSS Enterprise TLS` is a Windows Enterprise CA provider. It requests,
independently validates, and installs a localhost certificate from an Active
Directory Certificate Services (AD CS) Enterprise CA, and reports a durable,
structured outcome to the caller.

Since v0.3.0 enrollment runs in process, with no child process: a CNG key, a
CSR built in Go and the in-process `ICertRequest` client, driven by the durable
state machine in the `lifecycle` package. The `certreq.exe` workflow of earlier
versions is deprecated.

The supported target is Windows/amd64.

## Scope

Use this module when you need to:

- request a certificate for the expected `localhost` identity (`localhost`,
  `127.0.0.1`, and `::1`) from an AD CS Enterprise CA on Windows;
- enroll without child processes, with crash recovery from a protected journal;
- obtain structured outcomes, errors and cleanup results instead of parsing
  tool output.

## Non-scope

This module does not own local-CA creation, TLS serving/runtime configuration,
activation, rotation or general certificate management. An `ACCEPTED`
enrollment means "installed with a proven binding", not "in use". It validates
the expected localhost certificate properties; it is not a general-purpose
certificate validator.

## Resources

- [Technical documentation](docs/README.md)
- [Release notes v0.3.0](docs/release-notes-v0.3.0.md)
- [Examples](examples/)

## License

Apache License 2.0. See [LICENSE](LICENSE).
