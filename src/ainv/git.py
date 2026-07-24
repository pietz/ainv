"""Git-aware safeguards for plaintext dotenv destinations."""

from __future__ import annotations

import subprocess
from enum import StrEnum
from pathlib import Path


class GitDestinationStatus(StrEnum):
    """How Git treats a destination path."""

    OUTSIDE_WORKTREE = "outside-worktree"
    IGNORED = "ignored"
    UNTRACKED = "untracked"
    TRACKED = "tracked"


class GitSafetyError(Exception):
    """Git could not establish that a plaintext destination is safe."""


class GitInspectionError(GitSafetyError):
    """Git inspection failed and must not be treated as outside a worktree."""


def destination_status(path: Path) -> GitDestinationStatus:
    """Classify *path* without reading its contents."""
    directory = path.parent.resolve()
    if _nearest_git_marker(directory) is None:
        return GitDestinationStatus.OUTSIDE_WORKTREE

    git_path = Path("/usr/bin/git")
    if not git_path.is_file():
        raise GitInspectionError("Git is unavailable; destination safety is unknown")
    git = str(git_path)

    root_result = _git(git, directory, "rev-parse", "--show-toplevel")
    if root_result.returncode != 0:
        raise GitInspectionError("Git worktree inspection failed")

    root = Path(root_result.stdout.strip()).resolve()
    destination = path.resolve(strict=False)
    try:
        relative = destination.relative_to(root)
    except ValueError:
        return GitDestinationStatus.OUTSIDE_WORKTREE

    relative_path = str(relative)
    literal_pathspec = f":(literal){relative_path}"
    tracked = _git(git, root, "ls-files", "--error-unmatch", "--", literal_pathspec)
    if tracked.returncode == 0:
        return GitDestinationStatus.TRACKED
    if tracked.returncode != 1:
        raise GitInspectionError("Git tracked-file inspection failed")

    ignored = _git(
        git,
        root,
        "check-ignore",
        "--quiet",
        "--no-index",
        "--stdin",
        "-z",
        input_text=relative_path + "\x00",
    )
    if ignored.returncode == 0:
        return GitDestinationStatus.IGNORED
    if ignored.returncode == 1:
        return GitDestinationStatus.UNTRACKED
    raise GitInspectionError("Git ignore inspection failed")


def _nearest_git_marker(directory: Path) -> Path | None:
    for candidate in (directory, *directory.parents):
        marker = candidate / ".git"
        if marker.is_dir() or marker.is_file():
            return marker
    return None


def enforce_destination_policy(
    status: GitDestinationStatus,
    *,
    allow_tracked: bool,
    allow_unignored: bool,
) -> None:
    """Reject destinations likely to be committed unless explicitly allowed."""
    if status is GitDestinationStatus.TRACKED and not allow_tracked:
        raise GitSafetyError(
            "dotenv destination is tracked by Git; pass --allow-tracked to override"
        )
    if status is GitDestinationStatus.UNTRACKED and not allow_unignored:
        raise GitSafetyError(
            "dotenv destination is not ignored by Git; pass --allow-unignored to override"
        )


def _git(
    git: str,
    directory: Path,
    *arguments: str,
    input_text: str | None = None,
) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            [git, "-C", str(directory), *arguments],
            check=False,
            capture_output=True,
            text=True,
            timeout=5,
            input=input_text,
            env={
                "GIT_OPTIONAL_LOCKS": "0",
                "LC_ALL": "C",
                "PATH": "/usr/bin:/bin",
            },
        )
    except (OSError, subprocess.TimeoutExpired):
        raise GitInspectionError("Git inspection could not complete safely") from None
