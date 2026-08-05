from unittest.mock import patch

import pytest

from faire_cuan.retry import retry


class TestRetry:
    @patch("faire_cuan.retry.time.sleep")
    def test_returns_on_first_success_without_sleeping(self, mock_sleep):
        assert retry(lambda: 42) == 42
        mock_sleep.assert_not_called()

    @patch("faire_cuan.retry.time.sleep")
    def test_retries_until_success(self, mock_sleep):
        calls = iter([ValueError("boom"), "ok"])

        def flaky():
            v = next(calls)
            if isinstance(v, Exception):
                raise v
            return v

        assert retry(flaky, attempts=3) == "ok"

    @patch("faire_cuan.retry.time.sleep")
    def test_raises_last_exception_after_all_attempts_exhausted(self, mock_sleep):
        attempt_count = 0

        def always_fails():
            nonlocal attempt_count
            attempt_count += 1
            raise RuntimeError(f"fail #{attempt_count}")

        with pytest.raises(RuntimeError, match="fail #3"):
            retry(always_fails, attempts=3)

        assert attempt_count == 3

    @patch("faire_cuan.retry.time.sleep")
    def test_logs_retry_attempts(self, mock_sleep, caplog):
        calls = iter([RuntimeError("oops"), "ok"])

        def flaky():
            v = next(calls)
            if isinstance(v, Exception):
                raise v
            return v

        with caplog.at_level("WARNING", logger="faire_cuan.retry"):
            retry(flaky, attempts=2, delay=5.0)

        assert "Attempt 1/2 failed" in caplog.text
