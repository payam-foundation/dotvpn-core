# Contributing

Thanks for helping. dotvpn is source-available under the PolyForm Noncommercial License 1.0.0 (see `LICENSE`).

## Ground rules

- Open an issue before a large change. Small fixes can go straight to a pull request.
- Keep changes minimal: standard library first, no new dependency for what a few lines do, no placeholder code.
- Anything that two components must agree on belongs in `dotvpn-wire`. Do not import across `dotvpn-core`, `dotvpn-relay` and `dotvpn-client`.
- Never commit secrets, real hostnames or real IP addresses. Use documentation values (`example.com`, `203.0.113.0/24`).
- Security issues: follow `SECURITY.md`, not a public issue.

## Development

See the "Development" section of `README.md` for build and test commands. Run the full test suite for the repository you changed and, for `dotvpn-wire` changes, for its dependants and `dotvpn-lab` as well.

## Licence of contributions

By submitting a contribution you agree that it is licensed to Payam Foundation and to everyone else under the same terms as the repository, and that you have the right to submit it. Sign off commits with `git commit -s` (Developer Certificate of Origin).
