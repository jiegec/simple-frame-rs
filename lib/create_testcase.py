#!/usr/bin/env python3
"""
Generate SFrame testcases from gas/testsuite assembly files.

This script finds assembly files from ~/binutils-gdb/gas/testsuite/gas/cfi-sframe
based on the current architecture (e.g., x86_64 + common), assembles them,
and generates JSON testcases using the create_testcase Rust example.
"""

import argparse
import glob
import os
import platform
import subprocess
import sys
from pathlib import Path
from typing import List, Optional


# Architecture mapping from platform.machine() to binutils naming
ARCH_MAPPING = {
    "x86_64": "x86_64",
    "aarch64": "aarch64",
    "s390x": "s390x",
}


def get_current_arch() -> str:
    """Get the current architecture in binutils naming convention."""
    machine = platform.machine().lower()
    return ARCH_MAPPING.get(machine, machine)


def find_assembly_files(arch: str, binutils_path: str) -> List[str]:
    """
    Find assembly files for the given architecture.

    Looks for files matching:
    - cfi-sframe-{arch}-*.s (arch-specific)
    - cfi-sframe-common-*.s (common to all archs)
    """
    testdir = Path(binutils_path) / "gas" / "testsuite" / "gas" / "cfi-sframe"

    if not testdir.exists():
        print(f"Error: Test directory not found: {testdir}", file=sys.stderr)
        sys.exit(1)

    files = []

    # Find arch-specific files
    arch_pattern = str(testdir / f"cfi-sframe-{arch}-*.s")
    arch_files = glob.glob(arch_pattern)
    files.extend(arch_files)

    # Find common files
    common_pattern = str(testdir / "cfi-sframe-common-*.s")
    common_files = glob.glob(common_pattern)
    files.extend(common_files)

    # Sort for consistent ordering
    files.sort()

    return files


def get_binutils_version(as_path: Optional[str] = None) -> str:
    """Get the binutils version from as --version."""
    cmd = [as_path if as_path else "as", "--version"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
        # Parse version like "GNU assembler (GNU Binutils for Debian) 2.40"
        for line in result.stdout.split("\n"):
            if "GNU assembler" in line or "version" in line.lower():
                # Extract version number (e.g., 2.40)
                parts = line.split()
                for part in parts:
                    if "." in part and part[0].isdigit():
                        return part.strip(",;)")
        return "unknown"
    except Exception as e:
        print(f"Warning: Could not determine binutils version: {e}", file=sys.stderr)
        return "unknown"


def assemble_file(
    asm_path: str,
    output_path: str,
    custom_binutils_path: Optional[str] = None,
) -> bool:
    """Assemble a .s file to an object file with SFrame generation."""
    env = os.environ.copy()
    if custom_binutils_path:
        env["PATH"] = f"{custom_binutils_path}:{env.get('PATH', '')}"

    cmd = [
        "as",
        "--gsframe",  # Generate SFrame section
        "-o",
        output_path,
        asm_path,
    ]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, env=env)
        if result.returncode != 0:
            print(f"Error assembling {asm_path}: {result.stderr}", file=sys.stderr)
            return False
        return True
    except Exception as e:
        print(f"Error assembling {asm_path}: {e}", file=sys.stderr)
        return False


def link_file(
    obj_path: str,
    output_path: str,
    custom_binutils_path: Optional[str] = None,
) -> bool:
    """Link a .o file to an executable file."""
    env = os.environ.copy()
    if custom_binutils_path:
        env["PATH"] = f"{custom_binutils_path}:{env.get('PATH', '')}"

    cmd = [
        "ld",
        "-o",
        output_path,
        obj_path,
    ]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, env=env)
        if result.returncode != 0:
            print(f"Error linking {obj_path}: {result.stderr}", file=sys.stderr)
            return False
        return True
    except Exception as e:
        print(f"Error linking {obj_path}: {e}", file=sys.stderr)
        return False


def create_testcase_with_cargo(obj_path: str) -> bool:
    """Run the Rust create_testcase example to generate JSON."""
    try:
        result = subprocess.run(
            ["cargo", "run", "--example", "create_testcase", obj_path],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            print(f"Error running create_testcase: {result.stderr}", file=sys.stderr)
            return False
        print(result.stdout.strip())
        return True
    except Exception as e:
        print(f"Error running cargo: {e}", file=sys.stderr)
        return False


def main():
    parser = argparse.ArgumentParser(
        description="Generate SFrame testcases from gas/testsuite assembly files"
    )
    parser.add_argument(
        "--binutils-path",
        default=os.path.expanduser("~/binutils-gdb"),
        help="Path to binutils-gdb source directory",
    )
    parser.add_argument(
        "--custom-binutils-path",
        default=os.environ.get("CUSTOM_BINUTILS_PATH", ""),
        help="Path to custom binutils binaries (prepended to PATH)",
    )
    parser.add_argument(
        "--arch",
        default=get_current_arch(),
        help=f"Architecture to use (default: {get_current_arch()})",
    )
    parser.add_argument(
        "--output-dir",
        default="testcases",
        help="Output directory for testcases (default: testcases)",
    )
    parser.add_argument(
        "--keep-objects",
        action="store_true",
        help="Keep temporary object files",
    )
    parser.add_argument(
        "files",
        nargs="*",
        help="Specific assembly files to process (if not specified, finds all for arch)",
    )

    args = parser.parse_args()

    # Change to the script's directory (lib/) for cargo
    script_dir = Path(__file__).parent.absolute()
    os.chdir(script_dir)

    # Find assembly files
    if args.files:
        asm_files = args.files
    else:
        asm_files = find_assembly_files(args.arch, args.binutils_path)
        print(f"Found {len(asm_files)} assembly files for arch '{args.arch}'")

    if not asm_files:
        print("No assembly files found", file=sys.stderr)
        sys.exit(1)

    # Get binutils version for output naming
    as_path = None
    if args.custom_binutils_path:
        as_path = os.path.join(args.custom_binutils_path, "as")
    version = get_binutils_version(as_path)
    print(f"Using binutils version: {version}")

    # Process each assembly file
    success_count = 0
    temp_files = []

    for asm_path in asm_files:
        basename = Path(asm_path).stem
        print(f"\nProcessing {basename}...")

        # Create temporary object file
        obj_path = f"/tmp/{basename}.o"
        exe_path = f"/tmp/{basename}"
        temp_files.append(obj_path)
        temp_files.append(exe_path)

        # Assemble
        if not assemble_file(asm_path, obj_path, args.custom_binutils_path):
            print(f"  Failed to assemble, skipping...")
            continue

        # Link
        if not link_file(obj_path, exe_path, args.custom_binutils_path):
            print(f"  Failed to link, skipping...")
            continue

        # Check if SFrame section exists
        check_result = subprocess.run(
            ["objdump", "-h", exe_path],
            capture_output=True,
            text=True,
        )
        if ".sframe" not in check_result.stdout:
            print(f"  No SFrame section found, skipping...")
            continue

        # Use cargo example to create testcase
        if create_testcase_with_cargo(exe_path):
            # Rename the output file to include version
            src_json = Path(args.output_dir) / f"{basename}.json"
            dst_json = Path(args.output_dir) / f"{basename}-{version}.json"
            if src_json.exists():
                if dst_json.exists():
                    dst_json.unlink()
                src_json.rename(dst_json)
                print(f"  Renamed to {dst_json}")
                success_count += 1
            else:
                print(f"  Warning: Expected output file not found: {src_json}")
        else:
            print(f"  Failed to create testcase")

    # Cleanup
    if not args.keep_objects:
        for temp_file in temp_files:
            try:
                os.remove(temp_file)
            except:
                pass

    print(f"\nSuccessfully created {success_count} testcases")


if __name__ == "__main__":
    main()
