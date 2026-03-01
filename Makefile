.PHONY: install dev test lint typecheck format audit docs clean ci

install:
	pip install -e .

dev:
	pip install -e ".[dev]"

test:
	pytest --cov=threatcode --cov-report=term-missing -q

lint:
	ruff check src/ tests/

typecheck:
	mypy src/threatcode/

format:
	ruff format src/ tests/
	ruff check --fix src/ tests/

audit:
	pip-audit

docs:
	pip install -e ".[docs]"
	mkdocs serve

clean:
	rm -rf build/ dist/ *.egg-info .pytest_cache .mypy_cache .ruff_cache htmlcov/ .coverage
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true

ci: lint typecheck test audit
