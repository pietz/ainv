from pathlib import Path

import pytest

from ainv.git import (
    GitDestinationStatus,
    GitInspectionError,
    GitSafetyError,
    destination_status,
    enforce_destination_policy,
)


def test_classifies_tracked_ignored_and_untracked_files(tmp_path: Path) -> None:
    import subprocess

    subprocess.run(["git", "init", "--quiet", str(tmp_path)], check=True)
    (tmp_path / ".gitignore").write_text(".env\n")
    (tmp_path / "tracked.env").write_text("")
    (tmp_path / "[literal]*.env").write_text("")
    subprocess.run(
        [
            "git",
            "-C",
            str(tmp_path),
            "add",
            ".gitignore",
            "tracked.env",
            "[literal]*.env",
        ],
        check=True,
    )

    assert destination_status(tmp_path / "tracked.env") is GitDestinationStatus.TRACKED
    assert destination_status(tmp_path / ".env") is GitDestinationStatus.IGNORED
    assert destination_status(tmp_path / "other.env") is GitDestinationStatus.UNTRACKED
    assert (
        destination_status(tmp_path / "[literal]*.env") is GitDestinationStatus.TRACKED
    )

    linked_parent = tmp_path.parent / f"{tmp_path.name}-link"
    linked_parent.symlink_to(tmp_path, target_is_directory=True)
    try:
        assert (
            destination_status(linked_parent / "tracked.env")
            is GitDestinationStatus.TRACKED
        )
    finally:
        linked_parent.unlink()


def test_outside_worktree(tmp_path: Path) -> None:
    assert (
        destination_status(tmp_path / ".env") is GitDestinationStatus.OUTSIDE_WORKTREE
    )


def test_git_execution_failure_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import subprocess

    subprocess.run(["git", "init", "--quiet", str(tmp_path)], check=True)

    def fail(*args: object, **kwargs: object) -> None:
        raise subprocess.TimeoutExpired("git", 5)

    monkeypatch.setattr("ainv.git.subprocess.run", fail)

    with pytest.raises(GitInspectionError):
        destination_status(tmp_path / ".env")


@pytest.mark.parametrize(
    ("status", "allow_tracked", "allow_unignored", "raises"),
    [
        (GitDestinationStatus.TRACKED, False, False, True),
        (GitDestinationStatus.TRACKED, True, False, False),
        (GitDestinationStatus.UNTRACKED, False, False, True),
        (GitDestinationStatus.UNTRACKED, False, True, False),
        (GitDestinationStatus.IGNORED, False, False, False),
        (GitDestinationStatus.OUTSIDE_WORKTREE, False, False, False),
    ],
)
def test_enforces_explicit_overrides(
    status: GitDestinationStatus,
    allow_tracked: bool,
    allow_unignored: bool,
    raises: bool,
) -> None:
    if raises:
        with pytest.raises(GitSafetyError):
            enforce_destination_policy(
                status,
                allow_tracked=allow_tracked,
                allow_unignored=allow_unignored,
            )
    else:
        enforce_destination_policy(
            status,
            allow_tracked=allow_tracked,
            allow_unignored=allow_unignored,
        )
