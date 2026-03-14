# nostr-mcp coverage policy

date: 2026-03-14
status: active staged policy

## objective

The `0.1.0` line must end at `100/100/100/100` coverage for the shipped crate family:

- executable lines
- functions
- regions
- branches

Branch data is required in LCOV. Coverage without branch records is not release-valid.

## staged rollout

Coverage governance starts now. Blocking crate promotion happens later.

- `R7.1`: establish the coverage contract, validation tooling, and deterministic reporting surface
- `R7.2` through `R7.5`: continue hardening while coverage work expands crate by crate
- `R7.6`: define the public release-crate coverage target set and readiness contract
- later loops: raise each release crate to `100/100/100/100` before flipping blocking mode

The required crate set may remain empty only while the policy mode is `staged`.

## contract files

- `contract/coverage/rollout.toml`: threshold contract and rollout order
- `contract/coverage/release-crates.toml`: public `0.1.0` crate family that coverage promotion applies to
- `contract/coverage/required-crates.toml`: currently blocking crate set
- `contract/coverage/profiles.toml`: per-crate coverage run profile overrides

## tooling surface

- `cargo guard-coverage-contract`
- `cargo coverage-release-crates`
- `cargo coverage-required-crates`
- `cargo coverage-workspace-crates`
- `cargo coverage-run-crate -- --crate <name>`
- `cargo coverage-report -- --scope <scope> --summary <json> --lcov <info> --out <json>`

## operating rules

- thresholds stay strict from the start; rollout staging does not weaken the end-state target
- required crates must be a subset of the public release crate set
- required crates must be a subset of the rollout list and must be marked `required` there
- every workspace crate must appear exactly once in the rollout contract
- release crates must follow rollout order exactly
- coverage profiles must be explicit and deterministic
