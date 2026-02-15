# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- SFrame Version 3 support with full spec compliance
- Flexible FDE (SFRAME_FDE_TYPE_FLEX) support for v3
- s390x architecture support for both v2 and v3
- AArch64 Pointer Authentication (PAuth) key support in to_string()
- Version-agnostic API additions (`to_string`, offset getters)
- Fuzzing support with AFL harness
- Extensive test cases from binutils 2.40 to 2.46
- CI/CD pipeline for automated testing

### Changed

- Improved error handling for malformed input (fuzzing-driven fixes)
- Refactored module structure: moved v2 to submodule, added v1 and v3

### Fixed

- Fixed AArch64 RA/FP order in v1 and v2
- Fixed printing format to match binutils
- Fixed potential overflow panics found by fuzzing
- Fixed modulo zero edge case in PC mask handling

## [0.2.0] - 2025-10-01

### Added

- Example to dump backtrace of other programs using ptrace
- Utility function to search for FDE and FRE
- Utility function to get offset of CFA/RA/FP

## [0.1.0] - 2025-09-30

### Added

- Initial release with basic working SFrame v1/v2 support
- Support for AMD64 and AArch64 architectures
- Function to parse SFrame sections and print stack trace information
