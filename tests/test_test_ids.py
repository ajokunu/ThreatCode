"""A test id is short enough to be an environment variable on every platform.

While a test runs, pytest keeps its id in the ``PYTEST_CURRENT_TEST`` environment variable.
Windows refuses a variable of more than 32,767 characters, so a parametrized test whose value is
a 200,000 character string, and has no ``id=``, fails at setup and again at teardown there while
passing everywhere else.
The report of that failure repeats the id in every line of its traceback, which also made the
log of a failed run large enough to take minutes to print.
"""

from __future__ import annotations

import pytest

# Far below the Windows limit and far above the longest id the suite has: a parametrize value that
# gets near this is better named with ``pytest.param(..., id="...")``.
MAX_ID_CHARACTERS = 1_000


def overlong(node_ids: list[str], limit: int = MAX_ID_CHARACTERS) -> list[str]:
    """The start of every id longer than ``limit``, with its length."""
    return [
        f"{len(node_id)} characters: {node_id[:100]}"
        for node_id in node_ids
        if len(node_id) > limit
    ]


def test_no_test_in_this_session_has_an_overlong_id(request: pytest.FixtureRequest) -> None:
    found = overlong([item.nodeid for item in request.session.items])
    assert not found, "name the parameters with pytest.param(..., id='...'):\n" + "\n".join(found)


def test_an_overlong_id_is_found() -> None:
    long_id = "tests/test_a.py::test[" + "x" * 5_000 + "]"
    ids = ["tests/test_a.py::test[ok]", long_id]
    found = overlong(ids)
    assert len(found) == 1
    assert found[0].startswith(f"{len(long_id)} characters: ")
    assert overlong(ids[:1]) == []
