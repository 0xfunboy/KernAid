set shell := ["bash", "-euo", "pipefail", "-c"]

bootstrap:
    corepack enable
    pnpm install

format:
    cargo fmt --all --check
    pnpm format

lint:
    cargo clippy --workspace --all-targets -- -D warnings
    pnpm lint

check:
    cargo check --workspace
    pnpm check
    ./tools/verify-release/validate-schemas.sh

test:
    cargo test --workspace
    pnpm test
    python3 -m unittest discover -s tests/rescue -p 'test_*.py'
    just test-observe

test-observe:
    ./tests/integration/observe-zero-writes.sh

test-provider-contracts:
    pnpm --filter @kernaid/agent-gateway test

test-vault:
    @echo "Runs destructive storage commands only against an internally-created disposable loop image."
    sudo ./tools/test-vault/luks-roundtrip.sh

run-desk:
    pnpm run run:desk

build-rescue:
    ./tools/build-rescue/build.sh

qemu-bios:
    ./tools/build-rescue/qemu-smoke.sh bios

qemu-uefi:
    ./tools/build-rescue/qemu-smoke.sh uefi

qemu-secureboot:
    @echo "Secure Boot is an open release gate; no shipping signed boot chain exists yet."
    @exit 2

verify-release:
    ./tools/verify-release/verify.sh
