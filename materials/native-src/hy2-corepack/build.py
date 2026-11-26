#!/usr/bin/env python3
"""Rebuild the firmware's static, XZ-only mksquashfs with pinned local sources."""
import argparse
import hashlib
import os
from pathlib import Path
import shlex
import subprocess
import tarfile


SOURCES = {
    "squashfs-tools-4.6.1.tar.gz": "9c4974e07c61547dae14af4ed1f358b7d04618ae194e54d6be72ee126f0d2f53",
    "xz-5.8.4.tar.xz": "4ce24038fd4221e0d13bc1a2de7a4db56e90b92b3bf75321f6c14be73f65de4b",
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--zig", required=True, type=Path, help="Path to Zig 0.14.1")
    parser.add_argument("--work", required=True, type=Path, help="New build directory")
    args = parser.parse_args()
    zig = args.zig.resolve(strict=True)
    if subprocess.check_output([zig, "version"], text=True).strip() != "0.14.1":
        parser.error("This recipe uses Zig 0.14.1")
    work = args.work.resolve()
    # The upstream build systems split CC and flags on whitespace.
    if any(c.isspace() for c in str(work) + str(zig)):
        parser.error("Choose a Zig path and a build directory without whitespace")
    work.mkdir(mode=0o700, parents=True, exist_ok=False)
    for name, expected in SOURCES.items():
        archive = Path(__file__).resolve().with_name(name)
        if hashlib.sha256(archive.read_bytes()).hexdigest() != expected:
            raise RuntimeError(f"Upstream source checksum mismatch for {name}")
        with tarfile.open(archive, "r:*") as source:
            source.extractall(work, filter="data")

    xz = work / "xz-5.8.4"
    squashfs = work / "squashfs-tools-4.6.1" / "squashfs-tools"
    zig_cmd = shlex.quote(str(zig))
    cc = f"{zig_cmd} cc -target x86_64-linux-musl"
    ar = f"{zig_cmd} ar"
    env = {**os.environ, "LC_ALL": "C", "CC": cc, "AR": ar,
           "RANLIB": f"{zig_cmd} ranlib", "CFLAGS": "-O2"}
    subprocess.run(["./configure", "--host=x86_64-linux-musl", "--disable-shared",
                    "--enable-static", "--disable-doc", "--disable-nls", "--disable-xz",
                    "--disable-xzdec", "--disable-lzmadec", "--disable-scripts",
                    "--enable-threads=no", "--enable-encoders=lzma1,lzma2",
                    "--enable-decoders=lzma1,lzma2", "--disable-assembler"],
                   cwd=xz, env=env, check=True)
    lzma = xz / "src" / "liblzma"
    subprocess.run(["make", "-j4", "liblzma.la"], cwd=lzma, env=env, check=True)
    # Preset 0 uses the fast parser. 4.6.1 hardcodes preset 6 for every XZ block.
    wrapper = squashfs / "xz_wrapper.c"
    code = wrapper.read_text()
    default = "lzma_lzma_preset(&stream->opt, LZMA_PRESET_DEFAULT)"
    if code.count(default) != 1:
        raise RuntimeError("Unexpected Squashfs-tools XZ wrapper")
    wrapper.write_text(code.replace(default, "lzma_lzma_preset(&stream->opt, 0)"))
    subprocess.run(["make", "-j4", "mksquashfs", "CONFIG=1", "GZIP_SUPPORT=0",
                    "XZ_SUPPORT=1", "COMP_DEFAULT=xz",
                    "XATTR_SUPPORT=0", "XATTR_DEFAULT=0", "REPRODUCIBLE_DEFAULT=1",
                    f"CC={cc}", f"EXTRA_CFLAGS=-O2 -I{lzma}/api",
                    f"LDFLAGS=-static -s -L{lzma}/.libs"], cwd=squashfs, check=True)
    binary = squashfs / "mksquashfs"
    print(f"{hashlib.sha256(binary.read_bytes()).hexdigest()}  {binary}")


if __name__ == "__main__":
    main()
