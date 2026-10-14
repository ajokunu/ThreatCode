.PHONY: install dev test lint typecheck format audit docs docs-check smoke mitre-check clean ci

install:
	pip install -e .

dev:
	pip install -e ".[dev]"

test:
	pytest --cov=threatcode --cov-report=term-missing -q

# The whole repository, scripts included, so a script cannot fall behind the rules src follows.
lint:
	ruff check .
	ruff format --check .

typecheck:
	mypy src/threatcode/

format:
	ruff format .
	ruff check --fix .

audit:
	pip-audit

docs:
	pip install -e ".[docs]"
	mkdocs serve

# The documentation as CI builds it: warnings are errors.
docs-check:
	pip install -e ".[docs]"
	mkdocs build --strict

# Build the sdist and wheel, then install the wheel without extras in a clean virtualenv and
# scan examples with it. PYTHON selects the interpreter (default python3).
smoke:
	rm -rf dist
	$${PYTHON:-python3} -m build
	PYTHON=$${PYTHON:-python3} bash scripts/smoke_test_wheel.sh dist/*.whl

# Compare the committed ATT&CK tables with the release they pin (needs the network).
mitre-check:
	$${PYTHON:-python3} scripts/gen_mitre_db.py --check

clean:
	rm -rf build/ dist/ *.egg-info src/*.egg-info .pytest_cache .mypy_cache .ruff_cache htmlcov/ .coverage
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true

ci: lint typecheck test audit docs-check smoke
