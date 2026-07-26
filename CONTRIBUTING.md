# Contributing

## Workflow

1. Work from one linked GitHub issue.
2. Use `issue/<id>-<slug>` for the branch.
3. Keep at most one open pull request in this repository.
4. For implementation, preserve a test-only RED commit observed by CI before
   the implementation commit.
5. Run `./scripts/ci_local.sh`.
6. Link the applicable public companion documentation and evidence.
7. Squash merge only after CI and review gates pass.

Transport, protocol, recovery, scheduling, exported API, and observable
behavior changes trigger the public doc-gate. Vendor-specific semantics belong
in `helianthus-modbusreg`, not here.

## Evidence And Licensing

Do not submit credentials, private network details, customer identifiers,
restricted source material, or private-repository artifacts. By contributing,
you confirm the material can be published under this repository's AGPL-3.0
license or, for independently authored implementation-neutral protocol facts,
the designated CC0-1.0 documentation lane.

See the
[Helianthus licensing model](https://github.com/Project-Helianthus/.github/blob/main/LICENSING.md).
