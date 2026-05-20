# Kernels

This subproject builds custom Linux kernels for Marlin enclave images.

The initial kernel is an x86_64 QEMU-compatible kernel for the green testing
image. Its requested kernel options live directly in the Nix derivation and are
expanded with Kconfig into the complete `.config` passed to Nixpkgs.

The options are grouped by subsystem so QEMU boot requirements, NixOS initrd
requirements, dm-verity storage support, and TPM2 support can be trimmed
independently as the image becomes smaller.
