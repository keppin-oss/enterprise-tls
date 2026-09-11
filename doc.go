// Package enterprise is a standalone Windows Enterprise CA provider for
// Keppin localhost HTTPS. It requests and independently validates a
// machine/computer certificate from an Active Directory Certificate Services
// (AD CS) Enterprise CA using the native certreq.exe workflow.
//
// This module is deliberately narrow: it does not implement a local-TLS
// fallback, it does not create or install any local CA, and it contains no
// fallback/orchestration policy. Those concerns are external to this module.
package enterprise
