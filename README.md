# grantline

`grantline` is a small Rust authorization boundary for delegated agents. It
checks that every child mandate only narrows its parent, then evaluates a
proposed action against the resulting leaf mandate.

It catches capability widening, broader resource or counterparty selectors,
principal changes, budget increases, longer validity windows, unconsumed
delegation depth, and weakened human-approval thresholds. Authorization also
checks action, resource, model, counterparty, time, spend, tool-call, and token
limits.

## Install

```console
cargo install --path .
```

Requires stable Rust 1.85 or newer.

## Use

Verify a root-to-leaf chain:

```console
cargo run -- verify-chain examples/chain.json
```

Evaluate an action:

```console
cargo run -- authorize examples/mandate.json examples/request.json
```

Add `--format json` to either command for machine-readable output. Exit codes
are stable: `0` means allow, `2` means policy denial, and `1` means malformed
input or an operational error.

Selectors in `resources` and `counterparties` are exact strings or terminal
prefix globs such as `catalog/laptops/*`. A child selector must be contained by
a parent selector. Actions and model identifiers always use exact matching.
Timestamps are Unix seconds and expiry is exclusive.

## Mandate shape

```json
{
  "schema_version": 1,
  "id": "laptop-quotes",
  "principal": "example-co",
  "delegate": "comparison-agent",
  "parent_id": "procurement-root",
  "actions": ["quote"],
  "resources": ["catalog/laptops/*"],
  "models": ["approved-model-v1"],
  "counterparties": ["supplier/approved-*"],
  "budget": { "spend_cents": 3000, "tool_calls": 12, "tokens": 20000 },
  "valid_from": 1790541000,
  "expires_at": 1790580000,
  "remaining_delegations": 1,
  "approval_above_cents": 1500
}
```

The library API exposes `verify_chain` and `authorize` for embedding. Input
types reject unknown JSON fields so misspelled policy keys fail closed.

## Verify

```console
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
```

## Security boundary

`grantline` is a deterministic policy evaluator, not an identity or signature
system. Production callers must authenticate principals and delegates, verify
mandate integrity and freshness, prevent replay, and enforce the returned
decision at the side-effect boundary. This crate forbids unsafe Rust.

## License

MIT
