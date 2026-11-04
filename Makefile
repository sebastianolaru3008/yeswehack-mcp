.DEFAULT_GOAL := help
.PHONY: help build test test-live clean

help: ## Show this help
	@awk 'BEGIN {FS = ":.*## "} /^[a-zA-Z_-]+:.*## / {printf "  %-10s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

build: ## Build wheel and sdist into dist/
	uv build

test: ## Run offline test suite (no network after first uv sync)
	uv run pytest

test-live: ## Run READ-ONLY live tests against the real API (loads YWH_PAT from .env)
	@set -a; if [ -f ./.env ]; then . ./.env; fi; set +a; uv run pytest tests/test_live.py -m live

clean: ## Remove build artifacts and caches (keeps .venv, .env, config)
	rm -rf dist build *.egg-info .pytest_cache .ruff_cache
	find . -name __pycache__ -type d -not -path './.venv/*' -prune -exec rm -rf {} +
