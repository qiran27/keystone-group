"""Safely expand the pinned MediaBench II video archive and nested sources."""

import hashlib
import os
import shutil
import stat
import tarfile
import zipfile
from pathlib import Path, PurePosixPath


BASE = Path(__file__).resolve().parents[1]
ARCHIVE = BASE / "dist" / "mb2_video.tgz"
VENDOR = BASE / "vendor"
EXPECTED_SHA256 = "681c554c25ee08bde62c0d3c19ab30ef5a07494b8f3a61c00a33212a32f7d6e8"
SOURCE_ARCHIVES = {
    "mpeg2dec/mpeg2vidcodec_v12.tar.gz",
    "jpg2000dec/jasper-1.701.0.zip",
    "cjpeg/jpegsrc.v6b.tar.gz",
    "h263dec/tmndec-1.7.tar.gz",
    "h264dec/jm10.2.zip",
    "h263enc/tmn-1.7.tar.gz",
    "mpeg4dec/ffmpeg.2006_04_24.tgz",
}


def safe_target(root, name):
    path = PurePosixPath(name)
    if path.is_absolute() or ".." in path.parts or "\\" in name or ":" in name:
        raise ValueError(f"unsafe archive path: {name}")
    target = root.joinpath(*path.parts)
    if not target.resolve().is_relative_to(root.resolve()):
        raise ValueError(f"archive path escapes destination: {name}")
    return target


def extract_tar(archive, root):
    members = archive.getmembers()
    for member in members:
        safe_target(root, member.name)
        if not (member.isdir() or member.isfile() or member.issym() or member.islnk()):
            raise ValueError(f"unsupported archive entry: {member.name}")
    files = links = 0
    for member in members:
        if member.issym() or member.islnk():
            links += 1
            continue
        target = safe_target(root, member.name)
        if member.isdir():
            target.mkdir(parents=True, exist_ok=True)
        else:
            target.parent.mkdir(parents=True, exist_ok=True)
            if target.exists():
                raise ValueError(f"duplicate archive entry: {member.name}")
            with archive.extractfile(member) as source, target.open("xb") as dest:
                shutil.copyfileobj(source, dest)
            if os.name != "nt":
                target.chmod(member.mode & 0o777)
            files += 1
    return files, links


def extract_zip(archive, root):
    entries = archive.infolist()
    for entry in entries:
        safe_target(root, entry.filename)
        mode = (entry.external_attr >> 16) & 0o170000
        if mode == stat.S_IFLNK:
            raise ValueError(f"unexpected zip link: {entry.filename}")
    files = 0
    for entry in entries:
        target = safe_target(root, entry.filename)
        if entry.is_dir():
            target.mkdir(parents=True, exist_ok=True)
        else:
            target.parent.mkdir(parents=True, exist_ok=True)
            if target.exists():
                raise ValueError(f"duplicate archive entry: {entry.filename}")
            with archive.open(entry) as source, target.open("xb") as dest:
                shutil.copyfileobj(source, dest)
            files += 1
    return files


def main():
    if VENDOR.exists():
        raise FileExistsError(f"destination already exists: {VENDOR}")
    digest = hashlib.sha256(ARCHIVE.read_bytes()).hexdigest()
    if digest != EXPECTED_SHA256:
        raise ValueError(f"archive SHA-256 mismatch: {digest}")

    suite_root = VENDOR / "mediabench2_video"
    codec_root = VENDOR / "codecs"
    VENDOR.mkdir()
    with tarfile.open(ARCHIVE, "r:gz") as suite:
        suite_files, skipped_links = extract_tar(suite, VENDOR)
    if not suite_root.is_dir():
        raise ValueError("MediaBench II suite root missing after extraction")
    codec_root.mkdir()
    codec_files = 0
    for relative in sorted(SOURCE_ARCHIVES):
        source = suite_root / relative
        if not source.is_file():
            raise FileNotFoundError(source)
        if source.suffix == ".zip":
            with zipfile.ZipFile(source) as archive:
                codec_files += extract_zip(archive, codec_root)
        else:
            with tarfile.open(source, "r:gz") as archive:
                files, skipped = extract_tar(archive, codec_root)
                if skipped:
                    raise ValueError(f"nested source contains links: {source}")
                codec_files += files
    print(f"suite_files={suite_files} skipped_absolute_or_duplicate_links={skipped_links}")
    print(f"codec_source_files={codec_files} source_packages={len(SOURCE_ARCHIVES)}")
    print(f"source_archive_sha256={digest}")


if __name__ == "__main__":
    main()
