"""Database failures must not expose bound values in exception logs."""

import logging

import pytest
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError

from server.app.db import Database


@pytest.mark.parametrize("url", ["sqlite:///:memory:", "sqlite://"])
def test_failed_insert_hides_bound_values_in_traceback(url, caplog):
    db = Database(url)
    value = "audit-" + "synthetic-private-value"
    try:
        with db.engine.begin() as connection:
            connection.execute(text("CREATE TABLE privacy_test (value TEXT UNIQUE)"))
            insert = text("INSERT INTO privacy_test (value) VALUES (:value)")
            connection.execute(insert, {"value": value})
            with pytest.raises(IntegrityError) as caught:
                connection.execute(insert, {"value": value})
            with caplog.at_level(logging.ERROR, logger="pushgate.audit-test"):
                logging.getLogger("pushgate.audit-test").error(
                    "Database operation failed",
                    exc_info=(caught.type, caught.value, caught.tb),
                )
        assert value not in str(caught.value)
        assert value not in caplog.text
        # Keep the failed statement and exception type available for diagnosis.
        assert "INSERT INTO privacy_test" in caplog.text
        assert "IntegrityError" in caplog.text
        assert db.engine.hide_parameters is True
    finally:
        db.engine.dispose()
