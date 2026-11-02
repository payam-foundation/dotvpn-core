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

## Workflow

`main` is protected: no direct pushes. Every change is a pull request.

1. Branch from `main` as `type/short-slug` (`feat/`, `fix/`, `docs/`, `ci/`, `chore/`). External contributors fork.
2. Commit with sign-off: `git commit -s`.
3. Open a PR. The title must be a Conventional Commit (`feat: add X`, `fix(tunnel): Y`); it becomes the squash commit on `main`. Breaking change: `feat!: ...`.
4. Required checks (tests, security, PR title, DCO) must pass. Merges are squash-only with a linear history.
5. Releases are automated: release-please opens a release PR from the Conventional Commits on `main` (changelog and version bump). Merging it creates the tag `vX.Y.Z` and the release; the tag triggers the signed build. Never tag by hand.

`dotvpn-wire` releases first; dependants pin an exact wire tag in `go.mod` and Dependabot opens the bump PR.

### Side-by-side checkouts and worktrees

`go.mod` never carries a `replace`. To work on several repos at once, keep them as siblings and put an untracked `go.work` in the parent directory:

```sh
cd .. && go work init ./dotvpn-wire ./dotvpn-core ./dotvpn-relay ./dotvpn-client ./dotvpn-lab
```

Use a git worktree per task so the main checkout stays clean. Keep worktrees outside the repos:

```sh
git worktree add ../.worktrees/<repo>/<slug> -b <type>/<slug> origin/main
git worktree remove ../.worktrees/<repo>/<slug>   # after the PR merges
```

Inside a worktree the parent `go.work` does not list it, so run Go there with `GOWORK=off` (the pinned wire tag) or create a task-local `go.work` listing the worktrees you need.

## Licence of contributions

By submitting a contribution you agree that it is licensed to Payam Foundation and to everyone else under the same terms as the repository, and that you have the right to submit it. Sign off commits with `git commit -s` (Developer Certificate of Origin).
