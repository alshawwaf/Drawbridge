"""Regression tests for v1.0.0 ship-hardening fixes."""
import logging

import app.main as main


def test_setup_logging_tolerates_bad_level(monkeypatch):
    # An invalid DCSIM_LOG_LEVEL must NOT abort boot — fall back to INFO; numeric strings are honored.
    monkeypatch.setenv("DCSIM_LOG_LEVEL", "VERBOSE")
    main._setup_logging()                                  # must not raise
    assert logging.getLogger("dcsim").level == logging.INFO
    monkeypatch.setenv("DCSIM_LOG_LEVEL", "10")
    main._setup_logging()
    assert logging.getLogger("dcsim").level == 10
