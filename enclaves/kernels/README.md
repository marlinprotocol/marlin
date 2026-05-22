# Kernels

This subproject builds custom Linux kernels for Marlin enclave images. The
requested kernel options live in `fragments/` and are expanded with Kconfig
into the complete `.config` passed to Nixpkgs.

The options are grouped into feature fragments so the NixOS image config can
request kernel support for the pieces it imports, such as the base runtime,
read-only dm-verity storage, and networking.

Common options for a fragment live in `<name>.kconfig`. Optional variants are
included automatically when they exist, in this order:

- `<name>.kconfig`
- `<name>-<arch>.kconfig`
- `<name>-<target>.kconfig`
- `<name>-<arch>-<target>.kconfig`

Supported targets are `qemu` and `ec2`. The top-level kernel attrs expose both
targets as peers, and `default` is an alias for `ec2`.
