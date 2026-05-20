{
  nixpkgs,
  systemConfig,
}: let
  system = systemConfig.system;
  pkgs = nixpkgs.legacyPackages."${system}";
in
  if system != "x86_64-linux"
  then {}
  else let
    kernelVersion = "6.18.28";

    linuxSrc = pkgs.fetchurl {
      url = "https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-${kernelVersion}.tar.xz";
      hash = "sha256-82B4lINYbPiiC0qyv/526ta2LA2x7rDZFylEVsTXe3Q=";
    };

    marlinGreenConfig = pkgs.writeText "marlin-green-qemu.config" ''
      # Marlin green-image boot requirements on x86_64 QEMU.

      # Architecture.
      CONFIG_X86=y
      CONFIG_64BIT=y
      CONFIG_X86_64=y
      CONFIG_X86_CPUID=y
      CONFIG_X86_MSR=y
      CONFIG_X86_X2APIC=y
      CONFIG_X86_VERBOSE_BOOTUP=y
      CONFIG_HYPERVISOR_GUEST=y
      CONFIG_KVM_GUEST=y
      CONFIG_PARAVIRT=y
      CONFIG_NR_CPUS=240
      CONFIG_PVH=y
      CONFIG_RANDOMIZE_BASE=y
      CONFIG_RELOCATABLE=y

      # x86_64 mitigations.
      CONFIG_CPU_MITIGATIONS=y
      CONFIG_SPECULATION_MITIGATIONS=y
      CONFIG_RETPOLINE=y
      CONFIG_MITIGATION_RETPOLINE=y
      CONFIG_LEGACY_VSYSCALL_NONE=y

      # Kernel core.
      CONFIG_SECTION_MISMATCH_WARN_ONLY=y
      CONFIG_SMP=y
      CONFIG_INPUT=y
      CONFIG_PRINTK=y
      CONFIG_PRINTK_TIME=y
      CONFIG_UNIX98_PTYS=y
      CONFIG_FUTEX=y
      CONFIG_HIGH_RES_TIMERS=y
      CONFIG_GENERIC_CLOCKEVENTS=y
      CONFIG_NO_HZ=y
      CONFIG_NO_HZ_FULL=y
      CONFIG_POSIX_MQUEUE=y
      CONFIG_POSIX_TIMERS=y
      CONFIG_PROC_SYSCTL=y
      CONFIG_SHMEM=y
      CONFIG_KEYS=y
      CONFIG_HAVE_PERF_EVENTS=y
      CONFIG_PERF_EVENTS=y
      CONFIG_TASKSTATS=y
      CONFIG_TASK_DELAY_ACCT=y
      CONFIG_TASK_XACCT=y
      CONFIG_TASK_IO_ACCOUNTING=y

      # NixOS needs a modular kernel output even when most selected drivers are
      # built in.
      CONFIG_MODULES=y
      CONFIG_MODULE_UNLOAD=y

      # Executable formats.
      CONFIG_BINFMT_ELF=y
      CONFIG_BINFMT_SCRIPT=y
      CONFIG_BINFMT_MISC=y

      # Boot as a UKI through systemd-stub.
      CONFIG_ACPI=y
      CONFIG_EFI=y
      CONFIG_EFI_STUB=y
      CONFIG_EFIVAR_FS=y
      CONFIG_EFI_PARTITION=y

      # Load the NixOS initrd and expose early device nodes.
      CONFIG_BLK_DEV_INITRD=y
      CONFIG_BLK_DEV_LOOP=y
      CONFIG_BLOCK=y
      CONFIG_BLK_DEV=y
      CONFIG_RD_GZIP=y
      CONFIG_RD_XZ=y
      CONFIG_RD_ZSTD=y
      CONFIG_DEVTMPFS=y
      CONFIG_DEVTMPFS_MOUNT=y

      # Serial console.
      CONFIG_TTY=y
      CONFIG_SERIAL_8250=y
      CONFIG_SERIAL_8250_CONSOLE=y
      CONFIG_SERIAL_8250_PCI=y
      CONFIG_SERIAL_CORE=y
      CONFIG_SERIAL_CORE_CONSOLE=y
      CONFIG_SERIAL_EARLYCON=y

      # PCI transport for QEMU devices.
      CONFIG_PCI=y
      CONFIG_PCI_MSI=y
      CONFIG_PCI_MMCONFIG=y
      CONFIG_PCI_MSI_IRQ_DOMAIN=y
      CONFIG_GENERIC_MSI_IRQ=y
      CONFIG_GENERIC_MSI_IRQ_DOMAIN=y

      # Virtio devices used by QEMU.
      CONFIG_VIRTIO=y
      CONFIG_VIRTIO_MENU=y
      CONFIG_VIRTIO_PCI=y
      CONFIG_VIRTIO_PCI_LEGACY=y
      CONFIG_VIRTIO_BLK=y
      CONFIG_VIRTIO_CONSOLE=y
      CONFIG_VIRTIO_NET=y
      CONFIG_VIRTIO_BALLOON=y
      CONFIG_SCSI=y
      CONFIG_SCSI_LOWLEVEL=y
      CONFIG_SCSI_VIRTIO=y

      # Minimal pseudo filesystems and event APIs needed by systemd.
      CONFIG_PROC_FS=y
      CONFIG_SYSFS=y
      CONFIG_OVERLAY_FS=y
      CONFIG_TMPFS=y
      CONFIG_TMPFS_XATTR=y
      CONFIG_TMPFS_POSIX_ACL=y
      CONFIG_SIGNALFD=y
      CONFIG_TIMERFD=y
      CONFIG_EPOLL=y
      CONFIG_FHANDLE=y
      CONFIG_FSNOTIFY=y
      CONFIG_INOTIFY_USER=y
      CONFIG_FANOTIFY=y
      CONFIG_AUTOFS_FS=y
      CONFIG_DMIID=y
      CONFIG_SECCOMP=y
      CONFIG_SECCOMP_FILTER=y

      # Green images mount /usr from EROFS protected by dm-verity.
      CONFIG_MISC_FILESYSTEMS=y
      CONFIG_EROFS_FS=y
      CONFIG_EROFS_FS_XATTR=y
      CONFIG_EROFS_FS_ZIP=y
      CONFIG_EROFS_FS_SECURITY=y
      CONFIG_MD=y
      CONFIG_BLK_DEV_DM_BUILTIN=y
      CONFIG_BLK_DEV_DM=y
      CONFIG_DM_VERITY=y
      CONFIG_DM_INIT=y
      CONFIG_CRYPTO=y
      CONFIG_CRYPTO_HMAC=y
      CONFIG_CRYPTO_SHA256=y
      CONFIG_CRYPTO_USER_API=y
      CONFIG_CRYPTO_USER_API_HASH=y

      # Minimal systemd control-group support.
      CONFIG_BPF=y
      CONFIG_BPF_SYSCALL=y
      CONFIG_CGROUPS=y
      CONFIG_CGROUP_SCHED=y
      CONFIG_CGROUP_PIDS=y
      CONFIG_CGROUP_FREEZER=y
      CONFIG_CGROUP_DEVICE=y
      CONFIG_CGROUP_BPF=y
      CONFIG_MEMCG=y
      CONFIG_BLK_CGROUP=y

      # Minimal networking for the green testing image's SSH path.
      CONFIG_NET=y
      CONFIG_NET_CORE=y
      CONFIG_NETDEVICES=y
      CONFIG_ETHERNET=y
      CONFIG_UNIX=y
      CONFIG_PACKET=y
      CONFIG_INET=y

      # TPM2 devices exposed by QEMU.
      CONFIG_SECURITYFS=y
      CONFIG_HW_RANDOM=y
      CONFIG_HW_RANDOM_TPM=y
      CONFIG_TCG_TPM=y
      CONFIG_TCG_TIS_CORE=y
      CONFIG_TCG_TIS=y
      CONFIG_TCG_CRB=y
    '';

    config =
      pkgs.runCommand "marlin-qemu-linux-${kernelVersion}.config" {
        src = linuxSrc;
        nativeBuildInputs = [
          pkgs.buildPackages.stdenv.cc
          pkgs.buildPackages.bc
          pkgs.buildPackages.bison
          pkgs.buildPackages.flex
          pkgs.buildPackages.perl
        ];
      } ''
        unpackPhase
        cd linux-${kernelVersion}

        export ARCH=x86
        export KCONFIG_CONFIG="$PWD/.config"

        make KCONFIG_ALLCONFIG=${marlinGreenConfig} allnoconfig

        for option in \
          CONFIG_BINFMT_ELF \
          CONFIG_BLK_DEV_INITRD \
          CONFIG_BLK_DEV_LOOP \
          CONFIG_DEVTMPFS \
          CONFIG_DMIID \
          CONFIG_DM_VERITY \
          CONFIG_EROFS_FS \
          CONFIG_EFIVAR_FS \
          CONFIG_EFI_STUB \
          CONFIG_OVERLAY_FS \
          CONFIG_CRYPTO_HMAC \
          CONFIG_CRYPTO_USER_API_HASH \
          CONFIG_SECCOMP \
          CONFIG_TCG_CRB \
          CONFIG_TMPFS \
          CONFIG_VIRTIO_BLK \
          CONFIG_VIRTIO_CONSOLE \
          CONFIG_VIRTIO_NET \
          CONFIG_VIRTIO_PCI
        do
          grep -q "^$option=y$" "$KCONFIG_CONFIG"
        done

        cp "$KCONFIG_CONFIG" "$out"
      '';

    kernel = pkgs.linuxKernel.manualConfig {
      pname = "marlin-qemu-linux";
      version = kernelVersion;
      modDirVersion = kernelVersion;
      src = linuxSrc;
      configfile = config;
      allowImportFromDerivation = true;
      extraMeta = {
        description = "Minimal x86_64 QEMU Linux kernel for Marlin green images";
      };
    };
  in {
    default = kernel;
    inherit
      config
      kernel
      kernelVersion
      linuxSrc
      ;
  }
