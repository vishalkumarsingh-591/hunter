from __future__ import annotations

import io
import re
import shutil
import subprocess
import tarfile
import time
import uuid
from pathlib import Path
from urllib.parse import quote, urlparse

import httpx

from hunter.api.schemas import GitHubRepo
from hunter.logging import get_logger

_LOG = get_logger("hunter.github")
_TOKEN_VALID_RE = re.compile(r"^[A-Za-z0-9_\-\.]{20,255}$")

# Transient curl/git errors on Windows where a single retry usually succeeds.
_TRANSIENT_PATTERNS = (
    "getaddrinfo()",
    "could not resolve host",
    "thread failed to start",
    "ssl_read",
    "stream error in the http/2 framing layer",
    "rpc failed",
    "the requested url returned error: 5",
    "early eof",
    "connection reset",
    "operation timed out",
)


def _looks_transient(stderr: str) -> bool:
    low = stderr.lower()
    return any(p in low for p in _TRANSIENT_PATTERNS)

_GITHUB_RE = re.compile(
    r"(?:https?://)?(?:www\.)?github\.com[:/]+(?P<owner>[^/\s]+)/(?P<repo>[^/\s#?.]+)",
    re.IGNORECASE,
)


class GitHubError(Exception):
    pass


def list_repos(token: str, *, per_page: int = 30) -> list[GitHubRepo]:
    if not token:
        raise GitHubError("GitHub token required (HUNTER_GITHUB_TOKEN or X-GitHub-Token header)")
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    out: list[GitHubRepo] = []
    page = 1
    with httpx.Client(timeout=30.0) as client:
        while len(out) < 100:
            r = client.get(
                "https://api.github.com/user/repos",
                headers=headers,
                params={"per_page": per_page, "page": page, "sort": "updated"},
            )
            if r.status_code == 401:
                raise GitHubError("Invalid GitHub token")
            if r.status_code != 200:
                raise GitHubError(f"GitHub API error: {r.status_code}")
            batch = r.json()
            if not batch:
                break
            for item in batch:
                out.append(
                    GitHubRepo(
                        full_name=item["full_name"],
                        name=item["name"],
                        private=bool(item.get("private")),
                        default_branch=item.get("default_branch") or "main",
                        html_url=item.get("html_url", ""),
                        description=item.get("description"),
                    )
                )
            if len(batch) < per_page:
                break
            page += 1
    return out


def parse_github_url(url: str) -> tuple[str, str]:
    raw = (url or "").strip()
    if not raw:
        raise GitHubError("Repository URL is required")
    if raw.startswith("git@"):
        # git@github.com:owner/repo.git
        m = re.match(r"git@github\.com:(?P<owner>[^/]+)/(?P<repo>.+?)(?:\.git)?$", raw, re.I)
        if m:
            return m.group("owner"), m.group("repo").removesuffix(".git")
    m = _GITHUB_RE.search(raw)
    if m:
        owner = m.group("owner")
        repo = m.group("repo").removesuffix(".git")
        return owner, repo
    parsed = urlparse(raw)
    parts = [p for p in parsed.path.strip("/").split("/") if p]
    if len(parts) >= 2:
        return parts[0], parts[1].removesuffix(".git")
    raise GitHubError("Could not parse GitHub URL (expected https://github.com/owner/repo)")


def _sanitize_token(token: str | None) -> str | None:
    """Return a safe token or raise. None means no auth (public repos)."""
    if token is None:
        return None
    t = token.strip()
    if not t:
        return None
    if "://" in t or "@" in t or "/" in t or ":" in t or " " in t:
        raise GitHubError(
            "Invalid GitHub token: looks like a URL or path. "
            "Paste only your Personal Access Token (e.g. ghp_…), not a repository URL."
        )
    if not _TOKEN_VALID_RE.match(t):
        raise GitHubError(
            "Invalid GitHub token format. Expected a Personal Access Token "
            "(alphanumeric, 20+ characters, e.g. ghp_… or github_pat_…)."
        )
    return t


def _build_clone_cmd(url: str, dest: Path, ref: str | None) -> list[str]:
    """Build a git clone command with safety knobs that help on Windows.

    - ``http.version=HTTP/1.1`` avoids HTTP/2 stream multiplexing inside curl which is
      the trigger for ``getaddrinfo() thread failed to start`` and HTTP/2 framing errors.
    - ``http.postBuffer`` keeps large smart-protocol responses in memory.
    - ``--no-tags --single-branch`` reduces the working set considerably.
    """
    base = [
        "git",
        "-c",
        "http.version=HTTP/1.1",
        "-c",
        "http.postBuffer=524288000",
        "clone",
        "--depth",
        "1",
        "--no-tags",
        "--single-branch",
    ]
    if ref:
        base += ["--branch", ref]
    base += [url, str(dest)]
    return base


def _run_clone(cmd: list[str], env: dict[str, str], timeout: float = 600.0) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, check=True, capture_output=True, text=True, env=env, timeout=timeout)


def _download_tarball(
    *,
    owner: str,
    repo: str,
    dest: Path,
    token: str | None,
    ref: str | None,
    max_attempts: int = 3,
) -> Path:
    """Fetch a tarball via the GitHub API and extract it.

    Single HTTPS request avoids Windows-curl threading issues that break ``git clone``
    on large repos like WordPress/WordPress. Works for public repos with no auth and
    private repos with a PAT.
    """
    ref_segment = ref if ref else ""
    tar_url = f"https://api.github.com/repos/{owner}/{repo}/tarball/{ref_segment}".rstrip("/")
    headers: dict[str, str] = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "hunter-scanner",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"

    if dest.exists():
        shutil.rmtree(dest, ignore_errors=True)
    dest.mkdir(parents=True, exist_ok=True)

    last_err = ""
    for attempt in range(1, max_attempts + 1):
        try:
            with httpx.Client(
                follow_redirects=True,
                timeout=httpx.Timeout(connect=15.0, read=180.0, write=30.0, pool=30.0),
                http2=False,
            ) as client:
                with client.stream("GET", tar_url, headers=headers) as r:
                    if r.status_code == 401:
                        raise GitHubError("GitHub auth failed (check your token)")
                    if r.status_code == 404:
                        raise GitHubError(f"Repository or ref not found: {owner}/{repo} {ref or ''}".strip())
                    if r.status_code == 403 and "rate limit" in (r.text or "").lower():
                        raise GitHubError("GitHub rate limit exceeded — add a PAT to raise the limit")
                    if r.status_code != 200:
                        raise GitHubError(f"GitHub tarball download failed: HTTP {r.status_code}")
                    buf = io.BytesIO()
                    bytes_seen = 0
                    for chunk in r.iter_bytes(chunk_size=1024 * 256):
                        buf.write(chunk)
                        bytes_seen += len(chunk)
                        if bytes_seen > 2 * 1024 * 1024 * 1024:
                            raise GitHubError("Repository tarball exceeds 2 GiB; refusing to download")
            buf.seek(0)
            with tarfile.open(fileobj=buf, mode="r:gz") as tf:
                _safe_extract_tar(tf, dest)
            _LOG.info("github_tarball_downloaded", owner=owner, repo=repo, bytes=bytes_seen, attempt=attempt)
            return resolve_plugin_root(dest)
        except GitHubError:
            raise
        except (httpx.ReadError, httpx.ConnectError, httpx.ReadTimeout, httpx.RemoteProtocolError) as exc:
            last_err = f"{type(exc).__name__}: {exc}"
            _LOG.warning("github_tarball_transient", owner=owner, repo=repo, attempt=attempt, error=last_err[:200])
        except (tarfile.TarError, OSError) as exc:
            raise GitHubError(f"Could not extract tarball: {exc}") from exc
        if attempt < max_attempts:
            time.sleep(2 * attempt)

    raise GitHubError(
        f"GitHub tarball download failed after {max_attempts} attempts. Last error: {last_err[:200]}"
    )


def _safe_extract_tar(tf: tarfile.TarFile, dest: Path) -> None:
    """Extract tar safely (no path traversal, no symlinks outside dest)."""
    dest_resolved = dest.resolve()
    for member in tf.getmembers():
        if member.isdev():
            continue
        target = (dest / member.name).resolve()
        try:
            target.relative_to(dest_resolved)
        except ValueError:
            continue
        if member.issym() or member.islnk():
            continue
        try:
            tf.extract(member, dest, set_attrs=False)
        except (OSError, PermissionError):
            continue


def clone_repo(
    *,
    token: str | None,
    owner: str,
    repo: str,
    dest: Path,
    ref: str | None = None,
    max_attempts: int = 3,
) -> Path:
    """Materialize a GitHub repo into `dest`.

    Strategy: try the GitHub tarball API first (one HTTPS request, no git plumbing —
    survives Windows threading limits). If that fails for any reason, fall back to
    ``git clone`` with HTTP/1.1 and a couple of retries.
    """
    dest.parent.mkdir(parents=True, exist_ok=True)
    safe_token = _sanitize_token(token)

    try:
        return _download_tarball(
            owner=owner, repo=repo, dest=dest, token=safe_token, ref=ref, max_attempts=max_attempts
        )
    except GitHubError as exc:
        _LOG.warning("tarball_failed_fallback_git", owner=owner, repo=repo, error=str(exc)[:200])
        tarball_err = str(exc)

    url = f"https://github.com/{owner}/{repo}.git"
    env = {"GIT_TERMINAL_PROMPT": "0", "GIT_HTTP_LOW_SPEED_LIMIT": "1000", "GIT_HTTP_LOW_SPEED_TIME": "30"}
    if safe_token:
        url = f"https://x-access-token:{quote(safe_token, safe='')}@github.com/{owner}/{repo}.git"

    last_err = ""
    for attempt in range(1, max_attempts + 1):
        if dest.exists():
            shutil.rmtree(dest, ignore_errors=True)
        cmd = _build_clone_cmd(url, dest, ref)
        try:
            _run_clone(cmd, env)
            return resolve_plugin_root(dest)
        except FileNotFoundError as exc:
            raise GitHubError("git is not installed or not on PATH") from exc
        except subprocess.TimeoutExpired:
            last_err = "git clone timed out after 10 minutes"
            _LOG.warning("git_clone_timeout", owner=owner, repo=repo, attempt=attempt)
        except subprocess.CalledProcessError as exc:
            err = (exc.stderr or exc.stdout or "").strip()
            if safe_token:
                err = err.replace(safe_token, "***").replace(quote(safe_token, safe=""), "***")
            last_err = err or "git clone failed"
            _LOG.warning(
                "git_clone_failed",
                owner=owner,
                repo=repo,
                attempt=attempt,
                transient=_looks_transient(err),
                error=last_err[:200],
            )
            if not _looks_transient(err) or attempt == max_attempts:
                break
        if attempt < max_attempts:
            time.sleep(2 * attempt)

    raise GitHubError(
        f"Tarball download and git clone both failed. "
        f"Tarball error: {tarball_err[:120]}. Git error: {last_err[:120]}"
    )


def clone_from_url(
    *,
    repo_url: str,
    workspace: Path,
    token: str | None = None,
    ref: str | None = None,
    scan_id: str | None = None,
) -> tuple[Path, str]:
    owner, repo = parse_github_url(repo_url)
    sid = scan_id or uuid.uuid4().hex[:12]
    dest = workspace / "github" / owner / repo / sid
    root = clone_repo(token=token, owner=owner, repo=repo, dest=dest, ref=ref)
    return root, f"{owner}/{repo}"


def _php_file_count(path: Path, *, max_files: int = 5) -> int:
    """Count up to `max_files` *.php files recursively (cheap probe)."""
    n = 0
    try:
        for _ in path.rglob("*.php"):
            n += 1
            if n >= max_files:
                break
    except OSError:
        pass
    return n


def resolve_plugin_root(path: Path) -> Path:
    """Find the directory that actually contains the plugin's PHP source.

    Many WP plugin zips/repos extract with one or two wrapper directories above the real
    code (e.g. ``extracted/plugin-name-1.2.3/plugin-name/``). We walk down at most a few
    levels and pick the first directory that has any PHP files anywhere underneath it.
    """
    if not path.exists() or not path.is_dir():
        return path
    if (path / "composer.json").exists() or any(path.glob("*.php")):
        return path

    candidates: list[Path] = [path]
    # Walk down up to 3 wrapper levels.
    for _depth in range(3):
        new_candidates: list[Path] = []
        for cand in candidates:
            try:
                children = [
                    p
                    for p in cand.iterdir()
                    if p.is_dir() and not p.name.startswith(".") and p.name not in {"__MACOSX", "node_modules"}
                ]
            except OSError:
                children = []
            for child in children:
                if (child / "composer.json").exists() or any(child.glob("*.php")):
                    return child
                new_candidates.append(child)
        if not new_candidates:
            break
        candidates = new_candidates

    best: Path = path
    best_count = 0
    for cand in [path, *candidates]:
        try:
            children = [p for p in cand.iterdir() if p.is_dir() and not p.name.startswith(".")]
        except OSError:
            children = []
        for child in children:
            count = _php_file_count(child)
            if count > best_count:
                best = child
                best_count = count
    if best_count > 0:
        return best
    return path
