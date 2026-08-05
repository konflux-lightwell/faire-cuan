from faire_cuan.tekton import write_result


class TestWriteResult:
    def test_writes_named_file_with_value(self, tmp_path):
        write_result(tmp_path, "IMAGE_DIGEST", "sha256:deadbeef")

        assert (tmp_path / "IMAGE_DIGEST").read_text() == "sha256:deadbeef"

    def test_prints_value_to_stdout(self, tmp_path, capsys):
        write_result(tmp_path, "IMAGE_URL", "quay.io/org/repo:latest")

        assert capsys.readouterr().out == "quay.io/org/repo:latest\n"

    def test_creates_directory_if_missing(self, tmp_path):
        results_dir = tmp_path / "results"

        write_result(results_dir, "MY_RESULT", "some-value")

        assert (results_dir / "MY_RESULT").read_text() == "some-value"
