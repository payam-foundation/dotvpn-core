# Security policy

dotvpn is beta software used in hostile network environments. Please report vulnerabilities privately.

## Reporting

Use GitHub private vulnerability reporting: <https://github.com/payam-foundation/dotvpn-core/security/advisories/new>.

Do not open a public issue for a vulnerability. Include the affected version, a reproduction, and the impact you expect. We aim to acknowledge reports within 72 hours.

## Supported versions

Only the latest tagged release of each repository receives security fixes. A wire major version bump is a coordinated release of every component (see `dotvpn-wire`).

## Scope

In scope: authentication, tunnel confidentiality and integrity, probe resistance of the relay and node decoy, kill-switch and leak guards in the client, SSRF and egress guards in core.

Out of scope: claims that depend on a specific national censor's behaviour that cannot be reproduced, and denial of service by a network operator who simply blocks all traffic.
