"""Anchored file helpers shared by the bundled scripts (standard library only).

Every path is opened one component at a time from "/" with O_NOFOLLOW and
O_DIRECTORY, and all later work is relative to the resulting directory file
descriptor. A symlink anywhere in the path, or a component swapped for a
symlink during the walk, is refused; a component swapped for another
directory after it was listed is detected by device/inode comparison.

These guarantees need POSIX openat-style support (tested on Linux). On hosts
without it, ``require_host_support`` raises ``Unsupported`` and the scripts
exit with an explicit BLOCKED message instead of running with weaker checks.
Pass canonical paths: a symlinked ancestor such as a symlinked /tmp is refused.
"""

import errno
import os
import secrets
import stat

MAX_DEPTH = 64


class Unsupported(OSError):
    """The host cannot provide the containment guarantees these helpers need."""


class SkipFile(Exception):
    """Raised with a short reason code when a file must not be read."""


def probe_host_support():
    """Return None when the host has the needed primitives, else a BLOCKED message."""
    missing = [n for n in ("O_NOFOLLOW", "O_DIRECTORY") if not hasattr(os, n)]
    for fn, group in ((os.open, os.supports_dir_fd), (os.stat, os.supports_dir_fd), (os.rename, os.supports_dir_fd),
                      (os.unlink, os.supports_dir_fd), (os.stat, os.supports_follow_symlinks), (os.scandir, os.supports_fd)):
        if fn not in group:
            missing.append(fn.__name__)
    if os.name != "posix" or missing:
        return ("BLOCKED: host lacks anchored no-follow file operations (%s); run on a POSIX host with openat "
                "support or collect this evidence another way" % (", ".join(missing) or os.name))
    return None


HOST_SUPPORT_ERROR = probe_host_support()  # evaluated once, at import


def require_host_support():
    if HOST_SUPPORT_ERROR:
        raise Unsupported(HOST_SUPPORT_ERROR)


def _dir_flags():
    return os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)


def _canonical_hint(path):
    """Suggest the resolved path when a symlinked ancestor (e.g. macOS /tmp or /var) caused a refusal.

    The path is still refused: the caller decides whether that symlink is trusted.
    """
    real = os.path.realpath(path)
    if real != os.path.abspath(path) and os.path.isdir(real):
        return ("; if every symlink in it is a trusted system link (macOS /tmp and /var are), "
                "pass the canonical path instead: %s" % real)
    return ""


def open_dir(path):
    """Open ``path`` as a directory fd without following any symlink component."""
    require_host_support()
    parts = [p for p in os.path.abspath(path).split("/") if p]
    fd = os.open("/", _dir_flags())
    try:
        for part in parts:
            try:
                nfd = os.open(part, _dir_flags(), dir_fd=fd)
            except OSError as exc:
                if exc.errno in (errno.ELOOP, errno.ENOTDIR, errno.EMLINK):
                    raise OSError("refusing path %s: a component is a symlink or not a directory%s"
                                  % (path, _canonical_hint(path)))
                raise OSError("cannot open %s: %s" % (path, exc.strerror))
            os.close(fd)
            fd = nfd
        return fd
    except BaseException:
        os.close(fd)
        raise


def read_at(dir_fd, name, expected_stat, limit):
    """Read a regular file relative to ``dir_fd`` without following symlinks."""
    flags = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open(name, flags, dir_fd=dir_fd)
    except OSError:
        raise SkipFile("unreadable_or_swapped")
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise SkipFile("not_regular")
        if expected_stat is not None and (st.st_dev, st.st_ino) != (expected_stat.st_dev, expected_stat.st_ino):
            raise SkipFile("changed_during_walk")
        if st.st_size > limit:
            raise SkipFile("too_large")
        chunks, total = [], 0
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            total += len(chunk)
            if total > limit:
                raise SkipFile("too_large")
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        os.close(fd)


def read_file(path, limit):
    """Read one regular file through an anchored parent fd (no symlinks anywhere)."""
    parent, name = os.path.split(os.path.abspath(path))
    pfd = open_dir(parent or "/")
    try:
        return read_at(pfd, name, None, limit)
    finally:
        os.close(pfd)


def walk(root, prune=lambda rel, name: False):
    """Yield (kind, rel, dir_fd, name, stat) for every entry under ``root``.

    kind is one of: file, dir, symlink, special, excluded_dir, unreadable,
    changed_during_walk, max_depth_reached. ``dir_fd`` is valid only until the
    generator resumes. Directories are entered by fd, never by path.
    """
    rfd = open_dir(root)
    try:
        yield from _walk(rfd, "", prune, 0)
    finally:
        os.close(rfd)


def _walk(dfd, rel_dir, prune, depth):
    try:
        with os.scandir(dfd) as it:
            names = sorted(e.name for e in it)
    except OSError:
        yield ("unreadable", rel_dir or ".", None, None, None)
        return
    for name in names:
        rel = rel_dir + "/" + name if rel_dir else name
        try:
            st = os.stat(name, dir_fd=dfd, follow_symlinks=False)
        except OSError:
            yield ("unreadable", rel, dfd, name, None)
            continue
        if stat.S_ISLNK(st.st_mode):
            yield ("symlink", rel, dfd, name, st)
        elif stat.S_ISREG(st.st_mode):
            yield ("file", rel, dfd, name, st)
        elif not stat.S_ISDIR(st.st_mode):
            yield ("special", rel, dfd, name, st)
        elif prune(rel, name):
            yield ("excluded_dir", rel, dfd, name, st)
        elif depth >= MAX_DEPTH:
            yield ("max_depth_reached", rel, dfd, name, st)
        else:
            yield ("dir", rel, dfd, name, st)
            try:
                cfd = os.open(name, _dir_flags(), dir_fd=dfd)
            except OSError:
                yield ("changed_during_walk", rel, dfd, name, st)
                continue
            try:
                cst = os.fstat(cfd)
                if (cst.st_dev, cst.st_ino) != (st.st_dev, st.st_ino):
                    yield ("changed_during_walk", rel, dfd, name, st)
                    continue
                yield from _walk(cfd, rel, prune, depth + 1)
            finally:
                os.close(cfd)


def _write_all(fd, data):
    view = memoryview(data)
    while view:
        n = os.write(fd, view)
        view = view[n:]
    os.fsync(fd)


def safe_write(path, text, force=False):
    """Write ``text`` to ``path`` (mode 0600) relative to an anchored parent fd.

    Without ``force`` the file must not exist (O_EXCL). With ``force`` an
    existing regular file is replaced atomically by rename within the same
    parent fd; a symlink, directory or other non-regular target is refused.
    """
    abspath = os.path.abspath(path)
    parent, name = os.path.split(abspath)
    if not name or name in (".", ".."):
        raise OSError("output path must name a file")
    data = text.encode("utf-8")
    create = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    pfd = open_dir(parent or "/")
    try:
        if not force:
            try:
                fd = os.open(name, create, 0o600, dir_fd=pfd)
            except FileExistsError:
                raise OSError("%s exists; pass --force to replace it" % path)
            except OSError as exc:
                raise OSError("cannot create %s: %s" % (path, exc.strerror))
            try:
                _write_all(fd, data)
            finally:
                os.close(fd)
            return
        try:
            st = os.stat(name, dir_fd=pfd, follow_symlinks=False)
        except FileNotFoundError:
            st = None
        if st is not None and not stat.S_ISREG(st.st_mode):
            raise OSError("refusing to replace %s: not a regular file" % path)
        tmp = ".tmp-%d-%s" % (os.getpid(), secrets.token_hex(8))
        fd = os.open(tmp, create, 0o600, dir_fd=pfd)
        try:
            try:
                _write_all(fd, data)
            finally:
                os.close(fd)
            os.rename(tmp, name, src_dir_fd=pfd, dst_dir_fd=pfd)
        except BaseException:
            try:
                os.unlink(tmp, dir_fd=pfd)
            except OSError:
                pass
            raise
    finally:
        os.close(pfd)
