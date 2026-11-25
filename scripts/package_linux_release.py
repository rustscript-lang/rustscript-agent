#!/usr/bin/env python3
"""Build or verify the deterministic Linux x86_64 GNU release archive."""

from __future__ import annotations

import argparse
import gzip
import io
import os
from pathlib import Path, PurePosixPath
import re
import stat
import tarfile
import tempfile
import tomllib

TARGET = "x86_64-unknown-linux-gnu"
BINARIES = ("rustscript-agent", "rustscript-agent-gateway")
ROOT_FILES = ("README.md", "LICENSE", "CHANGELOG.md")
SEMVER = re.compile(
    r"^(0|[1-9][0-9]*)\."
    r"(0|[1-9][0-9]*)\."
    r"(0|[1-9][0-9]*)"
    r"(?:-((?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)"
    r"(?:\.(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*))*))?"
    r"(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$"
)


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


def canonical_relative_path(raw: str, label: str) -> PurePosixPath:
    path = PurePosixPath(raw)
    if (
        not raw
        or path.is_absolute()
        or raw != path.as_posix()
        or any(part in ("", ".", "..") for part in path.parts)
    ):
        raise ValueError(f"unsafe {label}: {raw!r}")
    return path


def inventory_lines(repository: Path, name: str) -> list[str]:
    path = regular_file(repository / "release" / name, f"release inventory {name}")
    lines = [
        line
        for line in path.read_text(encoding="utf-8").splitlines()
        if line and not line.startswith("#")
    ]
    if any(left >= right for left, right in zip(lines, lines[1:])):
        raise ValueError(f"release inventory {name} must be strictly sorted and unique")
    return lines


def package_version(repository: Path) -> str:
    manifest = regular_file(repository / "Cargo.toml", "Cargo.toml")
    with manifest.open("rb") as stream:
        value = tomllib.load(stream).get("package", {}).get("version")
    if not isinstance(value, str) or SEMVER.fullmatch(value) is None:
        raise ValueError("Cargo.toml package.version must be valid SemVer")
    return value


def parse_tag(tag: str) -> tuple[str, bool]:
    if not tag.startswith("v"):
        raise ValueError(f"tag {tag!r} must start with 'v'")
    version = tag[1:]
    match = SEMVER.fullmatch(version)
    if match is None:
        raise ValueError(f"tag {tag!r} must contain a valid SemVer version")
    return version, match.group(4) is not None


def validate_package_tag(repository: Path, tag: str) -> None:
    parse_tag(tag)
    expected_tag = f"v{package_version(repository)}"
    if tag != expected_tag:
        raise ValueError(f"tag {tag!r} does not match package version {expected_tag!r}")


def source_date_epoch() -> int:
    raw = os.environ.get("SOURCE_DATE_EPOCH")
    if raw is None:
        raise ValueError("SOURCE_DATE_EPOCH is required")
    if not re.fullmatch(r"0|[1-9][0-9]*", raw):
        raise ValueError("SOURCE_DATE_EPOCH must be a nonnegative integer")
    return int(raw, 10)


def add_inventory_file(
    files: dict[PurePosixPath, tuple[Path, int]],
    destination: PurePosixPath,
    source: Path,
    mode: int,
) -> None:
    if destination in files:
        raise ValueError(f"duplicate release destination: {destination}")
    files[destination] = (source, mode)


def mapped_inventory(repository: Path, name: str) -> list[tuple[PurePosixPath, Path]]:
    mappings: list[tuple[PurePosixPath, Path]] = []
    seen_sources: set[PurePosixPath] = set()
    seen_destinations: set[PurePosixPath] = set()
    for line in inventory_lines(repository, name):
        try:
            source_raw, destination_raw = line.split("\t")
        except ValueError as error:
            raise ValueError(
                f"release inventory {name} lines must be source<TAB>destination"
            ) from error
        source = canonical_relative_path(source_raw, f"source in {name}")
        destination = canonical_relative_path(
            destination_raw, f"destination in {name}"
        )
        if source in seen_sources:
            raise ValueError(f"duplicate source in {name}: {source}")
        if destination in seen_destinations:
            raise ValueError(f"duplicate destination in {name}: {destination}")
        seen_sources.add(source)
        seen_destinations.add(destination)
        mappings.append(
            (
                destination,
                regular_file(repository / source, f"production asset {source}"),
            )
        )
    return mappings


def inventory(repository: Path, binary_dir: Path) -> dict[PurePosixPath, tuple[Path, int]]:
    files: dict[PurePosixPath, tuple[Path, int]] = {}
    for name in BINARIES:
        add_inventory_file(
            files,
            PurePosixPath("bin", name),
            regular_file(binary_dir / name, f"binary {name}"),
            0o755,
        )
    for name in ROOT_FILES:
        add_inventory_file(
            files,
            PurePosixPath(name),
            regular_file(repository / name, name),
            0o644,
        )

    for source_raw in inventory_lines(repository, "rss-production.txt"):
        source = canonical_relative_path(source_raw, "RSS production source")
        try:
            relative = source.relative_to("rss")
        except ValueError as error:
            raise ValueError(f"RSS production source must be below rss/: {source}") from error
        add_inventory_file(
            files,
            PurePosixPath("share/rustscript-agent/rss") / relative,
            regular_file(repository / source, f"production RSS {source}"),
            0o644,
        )

    for name in ("schema-production.txt", "example-production.txt"):
        for destination, source in mapped_inventory(repository, name):
            add_inventory_file(files, destination, source, 0o644)
    return files


def manifest_bytes(files: dict[PurePosixPath, tuple[Path, int]]) -> bytes:
    paths = sorted([path.as_posix() for path in files] + ["MANIFEST.txt"])
    return ("\n".join(paths) + "\n").encode("utf-8")


def archive_directories(archive_root: str, relative_paths: list[str]) -> set[PurePosixPath]:
    root = PurePosixPath(archive_root)
    directories = {root}
    for relative in relative_paths:
        parent = root / PurePosixPath(relative).parent
        while parent != PurePosixPath("."):
            directories.add(parent)
            if parent == root:
                break
            parent = parent.parent
    return directories


def tar_info(
    name: str,
    mode: int,
    epoch: int,
    *,
    size: int = 0,
    directory: bool = False,
) -> tarfile.TarInfo:
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


def build_archive(repository: Path, tag: str, binary_dir: Path, output_dir: Path) -> Path:
    validate_package_tag(repository, tag)
    epoch = source_date_epoch()
    regular_directory(binary_dir, "binary directory")
    regular_directory(output_dir, "output directory")

    archive_root = f"rustscript-agent-{tag}-{TARGET}"
    output = output_dir / f"{archive_root}.tar.gz"
    files = inventory(repository, binary_dir)
    manifest = manifest_bytes(files)
    manifest_paths = sorted([path.as_posix() for path in files] + ["MANIFEST.txt"])
    directories = archive_directories(archive_root, manifest_paths)

    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{output.name}.", dir=output_dir
    )
    os.close(descriptor)
    temporary = Path(temporary_name)
    try:
        with temporary.open("wb") as raw:
            with gzip.GzipFile(
                filename="", mode="wb", fileobj=raw, mtime=epoch, compresslevel=9
            ) as compressed:
                with tarfile.open(
                    fileobj=compressed, mode="w", format=tarfile.GNU_FORMAT
                ) as archive:
                    for directory in sorted(
                        directories, key=lambda path: path.as_posix()
                    ):
                        name = directory.as_posix().rstrip("/") + "/"
                        archive.addfile(
                            tar_info(name, 0o755, epoch, directory=True)
                        )
                    for relative, (source, mode) in sorted(
                        files.items(), key=lambda item: item[0].as_posix()
                    ):
                        data = source.read_bytes()
                        name = (PurePosixPath(archive_root) / relative).as_posix()
                        archive.addfile(
                            tar_info(name, mode, epoch, size=len(data)),
                            io.BytesIO(data),
                        )
                    manifest_name = (
                        PurePosixPath(archive_root) / "MANIFEST.txt"
                    ).as_posix()
                    archive.addfile(
                        tar_info(
                            manifest_name, 0o644, epoch, size=len(manifest)
                        ),
                        io.BytesIO(manifest),
                    )
        os.replace(temporary, output)
    finally:
        temporary.unlink(missing_ok=True)
    return output


def normalize_tar_name(raw: str) -> str:
    if not raw or "\0" in raw or raw.startswith("/"):
        raise ValueError(f"unsafe tar member: {raw!r}")
    parts: list[str] = []
    for part in raw.rstrip("/").split("/"):
        if part == ".." or not part:
            raise ValueError(f"unsafe tar member: {raw!r}")
        if part != ".":
            parts.append(part)
    if not parts:
        raise ValueError(f"unsafe tar member: {raw!r}")
    return "/".join(parts)


def verify_archive(
    repository: Path,
    archive_path: Path,
    tag: str,
    binary_dir: Path,
    forbidden_byte_strings: list[str],
) -> None:
    validate_package_tag(repository, tag)
    epoch = source_date_epoch()
    regular_file(archive_path, "release archive")
    regular_directory(binary_dir, "binary directory")
    files = inventory(repository, binary_dir)
    manifest = manifest_bytes(files)
    expected_data = {
        path.as_posix(): (source.read_bytes(), mode)
        for path, (source, mode) in files.items()
    }
    expected_data["MANIFEST.txt"] = (manifest, 0o644)
    archive_root = f"rustscript-agent-{tag}-{TARGET}"
    expected_directories = {
        path.as_posix()
        for path in archive_directories(archive_root, list(expected_data))
    }
    forbidden = []
    for value in forbidden_byte_strings:
        if not value:
            raise ValueError("forbidden byte string must not be empty")
        forbidden.append(value.encode("utf-8"))

    with tarfile.open(archive_path, "r:gz") as archive:
        members = archive.getmembers()

        raw_seen: set[str] = set()
        normalized_seen: set[str] = set()
        normalized_names: list[str] = []
        for member in members:
            raw = member.name
            if raw in raw_seen:
                raise ValueError(f"duplicate raw tar member: {raw!r}")
            raw_seen.add(raw)
            normalized = normalize_tar_name(raw)
            if normalized in normalized_seen:
                raise ValueError(
                    f"duplicate normalized tar member: {normalized!r}"
                )
            normalized_seen.add(normalized)
            normalized_names.append(normalized)

        for member, normalized in zip(members, normalized_names):
            if member.name.rstrip("/") != normalized:
                raise ValueError(f"unsafe tar member: {member.name!r}")
            if not (member.isfile() or member.isdir()):
                raise ValueError(f"nonregular tar member: {member.name!r}")

        expected_member_count = len(expected_data) + len(expected_directories)
        if len(members) != expected_member_count:
            raise ValueError(
                f"raw tar member count mismatch: {len(members)} != {expected_member_count}"
            )

        member_map = dict(zip(normalized_names, members))
        if len(member_map) != len(members):
            raise ValueError("tar member names are not unique")
        actual_directories = {
            name for name, member in member_map.items() if member.isdir()
        }
        if actual_directories != expected_directories:
            raise ValueError("archive directory inventory mismatch")
        actual_files = {
            name.removeprefix(archive_root + "/"): member
            for name, member in member_map.items()
            if member.isfile() and name.startswith(archive_root + "/")
        }
        outside_files = [
            name
            for name, member in member_map.items()
            if member.isfile() and not name.startswith(archive_root + "/")
        ]
        if outside_files or set(actual_files) != set(expected_data):
            raise ValueError("archive regular-file inventory mismatch")
        if len(actual_files) != len(expected_data):
            raise ValueError("archive regular-file count mismatch")

        for normalized, member in member_map.items():
            if member.mtime != epoch:
                raise ValueError(f"wrong mtime for tar member: {normalized}")
            if member.uid != 0 or member.gid != 0:
                raise ValueError(f"wrong ownership for tar member: {normalized}")
            expected_mode = 0o755 if member.isdir() else expected_data[
                normalized.removeprefix(archive_root + "/")
            ][1]
            if member.mode != expected_mode:
                raise ValueError(f"wrong mode for tar member: {normalized}")

        for relative, member in actual_files.items():
            expected_bytes = expected_data[relative][0]
            if member.size != len(expected_bytes):
                raise ValueError(f"wrong size for archive member: {relative}")
            stream = archive.extractfile(member)
            if stream is None:
                raise ValueError(f"cannot read archive member: {relative}")
            data = stream.read()
            for marker in forbidden:
                if marker in data:
                    raise ValueError(
                        f"forbidden byte string found in archive member: {relative}"
                    )
            if data != expected_bytes:
                raise ValueError(f"wrong bytes for archive member: {relative}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tag", required=True)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--verify-archive", type=Path)
    mode.add_argument("--print-prerelease", action="store_true")
    parser.add_argument("--binary-dir", type=Path)
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--forbid-byte-string", action="append", default=[])
    arguments = parser.parse_args()
    if arguments.print_prerelease:
        if arguments.binary_dir or arguments.output_dir or arguments.forbid_byte_string:
            parser.error("--print-prerelease accepts only --tag")
    elif arguments.verify_archive:
        if arguments.binary_dir is None:
            parser.error("--verify-archive requires --binary-dir")
        if arguments.output_dir is not None:
            parser.error("--verify-archive does not accept --output-dir")
    else:
        if arguments.binary_dir is None or arguments.output_dir is None:
            parser.error("archive creation requires --binary-dir and --output-dir")
        if arguments.forbid_byte_string:
            parser.error("--forbid-byte-string requires --verify-archive")
    return arguments


def main() -> int:
    arguments = parse_args()
    repository = Path(__file__).resolve().parent.parent
    try:
        if arguments.print_prerelease:
            _, prerelease = parse_tag(arguments.tag)
            print(str(prerelease).lower())
        elif arguments.verify_archive:
            verify_archive(
                repository,
                arguments.verify_archive,
                arguments.tag,
                arguments.binary_dir,
                arguments.forbid_byte_string,
            )
            print(arguments.verify_archive)
        else:
            output = build_archive(
                repository,
                arguments.tag,
                arguments.binary_dir,
                arguments.output_dir,
            )
            print(output)
    except (OSError, ValueError, tarfile.TarError, tomllib.TOMLDecodeError) as error:
        raise SystemExit(f"error: {error}") from error
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
