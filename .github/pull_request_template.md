## What and why

<!-- What this changes and why it is needed. Link the issue it fixes, if any ("Fixes #123"). -->

## How it was tested

<!-- Unit tests, and for VM, cache, network or dashboard changes what you ran on a real kiln box. -->

## Checklist

- [ ] `cargo fmt --check`, `cargo clippy --all-targets --locked -- -D warnings` and `cargo test --locked` pass
- [ ] Dashboard changes: the inline-script check and `node src/dashboard.check.js src/dashboard.html` pass (see CONTRIBUTING.md)
- [ ] CHANGELOG.md updated under `Unreleased` for anything a user would notice
- [ ] Docs updated (docs/configuration.md for settings, SECURITY.md for security behaviour)
- [ ] No hostnames, tailnet names or addresses, private repo names, logins or home paths in code, tests, docs or this description
