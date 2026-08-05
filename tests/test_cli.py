from pathlib import Path
from unittest.mock import patch

from faire_cuan import OciVerifyError, VerificationError
from faire_cuan.cli import main
from faire_cuan.verify import VerifyResult


class TestNoSubcommand:
    def test_returns_2(self):
        assert main([]) == 2


class TestVerifyCommand:
    @patch("faire_cuan.commands.verify.write_result")
    @patch("faire_cuan.commands.verify.run_verify")
    def test_routes_to_run_verify_and_writes_fingerprint(self, mock_run_verify, mock_write_result, tmp_path):
        mock_run_verify.return_value = VerifyResult(fingerprint="SHA256:abc")
        results_dir = tmp_path / "results"
        results_dir.mkdir()

        rc = main(
            [
                "verify",
                "--source-image",
                "registry.io/img@sha256:def",
                "--key-file",
                "/tmp/key.pub",
                "--results-dir",
                str(results_dir),
            ]
        )

        assert rc == 0
        mock_run_verify.assert_called_once_with(
            "registry.io/img@sha256:def",
            Path("/tmp/key.pub"),
            ca_bundle=None,
        )
        mock_write_result.assert_called_once_with(
            results_dir,
            "VERIFICATION_KEY_FINGERPRINT",
            "SHA256:abc",
        )

    @patch("faire_cuan.commands.verify.run_verify")
    def test_verification_error_returns_12(self, mock_run_verify, tmp_path, capsys):
        mock_run_verify.side_effect = VerificationError("signature mismatch")

        rc = main(
            [
                "verify",
                "--source-image",
                "img@sha256:abc",
                "--key-file",
                "/key.pub",
                "--results-dir",
                str(tmp_path),
            ]
        )

        # This status code was lifted from the original bash script
        # TODO: verify if this status code is intentional
        assert rc == 12
        assert "signature mismatch" in capsys.readouterr().err


class TestMirrorCommand:
    @patch("faire_cuan.commands.mirror.run_mirror")
    def test_routes_to_run_mirror(self, mock_run_mirror):
        rc = main(
            [
                "mirror",
                "--source-image",
                "src@sha256:abc",
                "--image",
                "dest:latest",
            ]
        )

        assert rc == 0
        mock_run_mirror.assert_called_once_with(
            "src@sha256:abc",
            "dest:latest",
            ca_bundle=None,
        )


class TestResultsCommand:
    @patch("faire_cuan.commands.results.write_result")
    @patch("faire_cuan.commands.results.run_results")
    def test_routes_to_run_results_and_writes_all_outputs(self, mock_run_results, mock_write_result, tmp_path):
        from faire_cuan.results import GitCoordinates, ImageInfo, ResultsOutput

        mock_run_results.return_value = ResultsOutput(
            image=ImageInfo(
                image_url="quay.io/org/repo:tag",
                image_digest="sha256:aaa",
                image_ref="quay.io/org/repo@sha256:aaa",
            ),
            git=GitCoordinates(url="https://github.com/org/repo", commit="abc123"),
            sbom_blob_url="quay.io/org/repo:sha256-aaa.sbom",
        )
        workdir = tmp_path / "work"
        results_dir = tmp_path / "results"

        rc = main(
            [
                "results",
                "--source-image",
                "src@sha256:abc",
                "--image",
                "dest:tag",
                "--workdir",
                str(workdir),
                "--results-dir",
                str(results_dir),
            ]
        )

        assert rc == 0
        assert mock_write_result.call_count == 6


class TestErrorHandling:
    @patch("faire_cuan.commands.verify.run_verify")
    def test_oci_verify_error_returns_1(self, mock_run_verify, tmp_path, capsys):
        mock_run_verify.side_effect = OciVerifyError("something broke")

        rc = main(
            [
                "verify",
                "--source-image",
                "img@sha256:abc",
                "--key-file",
                "/key.pub",
                "--results-dir",
                str(tmp_path),
            ]
        )

        assert rc == 1
        assert "something broke" in capsys.readouterr().err
