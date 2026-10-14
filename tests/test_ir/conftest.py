"""Fixtures for the graph and recording tests."""

from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def charts_are_rendered_by_the_built_in_renderer(monkeypatch: pytest.MonkeyPatch) -> None:
    """Render Helm charts with the built-in renderer, whether or not ``helm`` is installed.

    The golden recordings and the graph tests hold for one renderer.
    On a machine with the ``helm`` binary the default mode would use it, and the two renderers
    only agree on the charts of the fixtures by luck.
    A test that wants another mode sets ``THREATCODE_HELM`` itself.
    """
    monkeypatch.setenv("THREATCODE_HELM", "off")
