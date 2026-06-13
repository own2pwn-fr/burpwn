# burpwn — common dev tasks. `make help` lists targets.
.DEFAULT_GOAL := help
PREFIX ?= $(HOME)/.local

.PHONY: help build release test fmt fmt-check clippy lint install ca doctor clean

help: ## Show this help
	@grep -hE '^[a-z-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'

build: ## Debug build of the whole workspace
	cargo build

release: ## Release build of the burpwn binary
	cargo build --release --bin burpwn

test: ## Run the workspace test suite (privileged sandbox test is #[ignore]d)
	cargo test --workspace --all-features

fmt: ## Format the workspace
	cargo fmt --all

fmt-check: ## Check formatting (CI)
	cargo fmt --all --check

clippy: ## Clippy with warnings denied (CI)
	cargo clippy --workspace --all-targets --all-features -- -D warnings

lint: fmt-check clippy ## fmt-check + clippy

install: release ## Build release and install via ./install.sh (PREFIX=$(PREFIX))
	PREFIX=$(PREFIX) ./install.sh

ca: ## Generate/locate the MITM CA
	cargo run --release --bin burpwn -- ca init

doctor: ## Check rootless prerequisites
	cargo run --release --bin burpwn -- doctor

clean: ## Remove build artifacts
	cargo clean
