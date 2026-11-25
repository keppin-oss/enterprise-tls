// Package enterprise is a standalone Windows Enterprise CA provider for
// Keppin localhost HTTPS. It requests and independently validates a
// machine/computer certificate from an Active Directory Certificate Services
// (AD CS) Enterprise CA.
//
// Enrollment runs through lifecycle.Enrollment with the native adapters of
// this package: CNGKeys, NativeRequester (Go CSR, in-process ICertRequest),
// MachineMy, AttemptDeleter and EnrollmentValidator. No child process is
// started and certreq.exe is not used.
//
// The lifecycle subpackage provides the durable enrollment state machine,
// process guards, consumer-side activation fencing and terminal cleanup.
// Local-TLS fallback, local CA creation and TLS serving remain consumer concerns.
package enterprise
