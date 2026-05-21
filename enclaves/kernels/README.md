# Kernels

This subproject builds custom Linux kernels for Marlin enclave images.

The initial kernel is an x86_64 QEMU-compatible kernel for the green testing
image. Its requested kernel options live in `fragments/` and are expanded with
Kconfig into the complete `.config` passed to Nixpkgs.

The options are grouped into feature fragments so the NixOS image config can
request kernel support for the pieces it imports, such as the base runtime,
read-only dm-verity storage, and networking.

Common options for a fragment live in `<name>.kconfig`. Arch-specific options
live in `<name>-<arch>.kconfig` and are included automatically when that arch
file exists.
