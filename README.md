# Keppin-OSS Enterprise TLS

`Keppin-OSS Enterprise TLS` is a Windows Enterprise CA provider. It requests,
independently validates, and installs a localhost certificate from an Active
Directory Certificate Services (AD CS) Enterprise CA using the native
`certreq.exe` workflow, and returns structured status, key-state, and cleanup
metadata to the caller.

The supported and verified target is Windows/amd64.

## Scope

Use this module when you need to:

- request a certificate for the expected `localhost` identity (`localhost`,
  `127.0.0.1`, and `::1`) from an AD CS Enterprise CA on Windows;
- obtain structured status, error, and key-state information instead of parsing
  tool output.

## Non-scope

This module does not own local-CA creation, TLS serving/runtime configuration,
or general certificate management. It validates the expected localhost
certificate properties; it is not a general-purpose certificate validator.

## Resources

- [Technical documentation](docs/README.md)
- [Examples](examples/)

## License

Apache License 2.0. See [LICENSE](LICENSE).
