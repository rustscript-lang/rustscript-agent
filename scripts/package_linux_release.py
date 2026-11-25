#!/usr/bin/env python3
"""Build the deterministic Linux x86_64 GNU release archive."""

from __future__ import annotations

import argparse
import gzip
import io
import os
from pathlib import Path, PurePosixPath
import stat
import tarfile
import tempfile
import tomllib

TARGET = "x86_64-unknown-linux-gnu"
BINARIES = ("rustscript-agent", "rustscript-agent-gateway")
ROOT_FILES = ("README.md", "LICENSE", "CHANGELOG.md")


def regular_file(path: Path, label: str) -> Path:
    try:
        metadata = path.lstat()
    except FileNotFoundError as error:
        raise ValueError(f"missing {label}: {path}") from error
    if stat.S_ISLNK(metadata.st_mode):
        raise ValueError(f"{label} must not be a symlink: {path}")
    if not stat.S_ISREG(metadata.st_mode):
        raise ValueError(f"{label} must be a regular file: {path}")
    return path


def regular_directory(path: Path, label: str) -> Path:
    try:
        metadata = path.lstat()
    except FileNotFoundError as error:
        raise ValueError(f"missing {label}: {path}") from error
    if stat.S_ISLNK(metadata.st_mode):
        raise ValueError(f"{label} must not be a symlink: {path}")
    if not stat.S_ISDIR(metadata.st_mode):
        raise ValueError(f"{label} must be a directory: {path}")
    return path


def walk_regular_files(root: Path, suffix: str) -> list[Path]:
    regular_directory(root, "asset directory")
    found: list[Path] = []
    pending = [root]
    while pending:
        directory = pending.pop()
        entries = sorted(directory.iterdir(), key=lambda path: path.name)
        for path in entries:
            metadata = path.lstat()
            if stat.S_ISLNK(metadata.st_mode):
                raise ValueError(f"asset tree must not contain symlinks: {path}")
            if stat.S_ISDIR(metadata.st_mode):
                pending.append(path)
            elif stat.S_ISREG(metadata.st_mode):
                if path.suffix == suffix:
                    found.append(path)
            else:
                raise ValueError(f"asset tree contains a nonregular source: {path}")
    return sorted(found, key=lambda path: path.relative_to(root).as_posix())


def package_version(repository: Path) -> str:
    manifest = regular_file(repository / "Cargo.toml", "Cargo.toml")
    with manifest.open("rb") as stream:
        value = tomllib.load(stream).get("package", {}).get("version")
    if not isinstance(value, str) or not value:
        raise ValueError("Cargo.toml package.version must be a nonempty string")
    return value


def source_date_epoch() -> int:
    raw = os.environ.get("SOURCE_DATE_EPOCH")
    if raw is None:
        raise ValueError("SOURCE_DATE_EPOCH is required")
    try:
        epoch = int(raw, 10)
    except ValueError as error:
        raise ValueError("SOURCE_DATE_EPOCH must be a nonnegative integer") from error
    if epoch < 0:
        raise ValueError("SOURCE_DATE_EPOCH must be a nonnegative integer")
    return epoch


def inventory(repository: Path, binary_dir: Path) -> dict[PurePosixPath, tuple[Path, int]]:
    files: dict[PurePosixPath, tuple[Path, int]] = {}
    for name in BINARIES:
        files[PurePosixPath("bin", name)] = (
            regular_file(binary_dir / name, f"binary {name}"),
            0o755,
        )
    for name in ROOT_FILES:
        files[PurePosixPath(name)] = (
            regular_file(repository / name, name),
            0o644,
        )

    rss_root = repository / "rss"
    for source in walk_regular_files(rss_root, ".rss"):
        relative = PurePosixPath(source.relative_to(rss_root).as_posix())
        files[PurePosixPath("share/rustscript-agent/rss") / relative] = (source, 0o644)

    schema_root = repository / "schemas"
    for source in walk_regular_files(schema_root, ".yaml"):
        relative = PurePosixPath(source.relative_to(schema_root).as_posix())
        files[PurePosixPath("share/rustscript-agent/schemas") / relative] = (source, 0o644)

    example_root = repository / "examples"
    for source in walk_regular_files(example_root, ".rss"):
        relative = PurePosixPath(source.relative_to(example_root).as_posix())
        files[PurePosixPath("share/rustscript-agent/examples") / relative] = (source, 0o644)

    for name in ("config.yaml", "auth.yaml"):
        source = regular_file(repository / "docs/examples" / name, f"example {name}")
        files[PurePosixPath("share/rustscript-agent/examples") / name] = (source, 0o644)
    return files


def tar_info(name: str, mode: int, epoch: int, *, size: int = 0, directory: bool = False) -> tarfile.TarInfo:
    info = tarfile.TarInfo(name)
    info.mode = mode
    info.uid = 0
    info.gid = 0
    info.uname = ""
    info.gname = ""
    info.mtime = epoch
    info.size = size
    if directory:
        info.type = tarfile.DIRTYPE
    return info


def build_archive(tag: str, binary_dir: Path, output_dir: Path) -> Path:
    repository = Path(__file__).resolve().parent.parent
    expected_tag = f"v{package_version(repository)}"
    if tag != expected_tag:
        raise ValueError(f"tag {tag!r} does not match package version {expected_tag!r}")
    epoch = source_date_epoch()
    regular_directory(binary_dir, "binary directory")
    regular_directory(output_dir, "output directory")

    archive_root = f"rustscript-agent-{tag}-{TARGET}"
    output = output_dir / f"{archive_root}.tar.gz"
    files = inventory(repository, binary_dir)
    manifest_paths = sorted([path.as_posix() for path in files] + ["MANIFEST.txt"])
    manifest = ("\n".join(manifest_paths) + "\n").encode("utf-8")

    directories = {PurePosixPath(archive_root)}
    for relative in manifest_paths:
        parent = PurePosixPath(archive_root) / PurePosixPath(relative).parent
        while parent != PurePosixPath("."):
            directories.add(parent)
            if parent == PurePosixPath(archive_root):
                break
            parent = parent.parent

    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{output.name}.", dir=output_dir)
    os.close(descriptor)
    temporary = Path(temporary_name)
    try:
        with temporary.open("wb") as raw:
            with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=epoch, compresslevel=9) as compressed:
                with tarfile.open(fileobj=compressed, mode="w", format=tarfile.GNU_FORMAT) as archive:
                    for directory in sorted(directories, key=lambda path: path.as_posix()):
                        name = directory.as_posix().rstrip("/") + "/"
                        archive.addfile(tar_info(name, 0o755, epoch, directory=True))
                    for relative, (source, mode) in sorted(files.items(), key=lambda item: item[0].as_posix()):
                        data = source.read_bytes()
                        name = (PurePosixPath(archive_root) / relative).as_posix()
                        archive.addfile(tar_info(name, mode, epoch, size=len(data)), io.BytesIO(data))
                    manifest_name = (PurePosixPath(archive_root) / "MANIFEST.txt").as_posix()
                    archive.addfile(
                        tar_info(manifest_name, 0o644, epoch, size=len(manifest)),
                        io.BytesIO(manifest),
                    )
        os.replace(temporary, output)
    finally:
        temporary.unlink(missing_ok=True)
    return output


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--binary-dir", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    return parser.parse_args()


def main() -> int:
    arguments = parse_args()
    try:
        output = build_archive(arguments.tag, arguments.binary_dir, arguments.output_dir)
    except (OSError, ValueError, tomllib.TOMLDecodeError) as error:
        raise SystemExit(f"error: {error}") from error
    print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
