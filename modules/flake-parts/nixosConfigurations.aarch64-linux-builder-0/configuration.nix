{
  config,
  inputs,
  self,
  pkgs,
  lib,
  ...
}:
# Hetzner CAX41 #54523394
# UEFI - came with this setting from the factory
{
  imports = [
    inputs.disko.nixosModules.disko
    inputs.srvos.nixosModules.server
    inputs.srvos.nixosModules.hardware-hetzner-cloud-arm
    inputs.srvos.nixosModules.roles-nix-remote-builder
    self.nixosModules.holo-users

    inputs.sops-nix.nixosModules.sops

    ../../nixos/shared.nix
    ../../nixos/shared-nix-settings.nix
    ../../nixos/shared-linux.nix

    self.nixosModules.shared-monitoring-clients
  ];

  passthru = {
    fqdn = "${config.passthru.hostName}.${config.passthru.domain}";

    domain = self.specialArgs.infraDomain;
    hostName = "aarch64-linux-builder-0"; # Define your hostname.

    primaryIpv4 = "65.21.51.86";
    primaryIpv6 = "2a01:4f9:c012:da4c::1/64";
  };

  networking = {
    inherit (config.passthru) hostName domain;
  };
  hostName = config.passthru.primaryIpv4;

  nix.settings.max-jobs = 16;

  roles.nix-remote-builder.schedulerPublicKeys = [
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINQ22z5rDdCLYH+MEoEt+tXJXTJqoeZNqvJl2n4aB+Kn steveej@steveej-x13s"
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBqhOu9oMwDlfQFRTBKAdCe4IZmcGrrbDABP576Q+BYW root@buildbot-nix-0"
  ];

  boot.kernelPackages = pkgs.linuxPackages_latest;

  disko.devices.disk.sda = {
    device = "/dev/sda";
    type = "disk";
    content = {
      type = "gpt";
      partitions = {
        ESP = {
          priority = 100;
          start = "2M";
          size = "500M";
          type = "EF00";
          content = {
            type = "filesystem";
            format = "vfat";
            extraArgs = [
              "-F"
              "16"
            ];
            mountpoint = "/boot";
            mountOptions = [ "umask=0077" ];
          };
        };

        root = {
          size = "100%";
          content = {
            type = "btrfs";
            extraArgs = [ "-f" ]; # Override existing partition
            mountpoint = "/partition-root";
            subvolumes = {
              # Subvolume name is different from mountpoint
              "/rootfs" = {
                mountpoint = "/";
              };
              "/nix" = {
                mountOptions = [
                  "compress=zstd"
                  "noatime"
                ];
                mountpoint = "/nix";
              };
              "/swap" = {
                mountpoint = "/.swapvol";
                swap.swapfile.size = "32G";
              };
            };
          };
        };
      };
    };
  };

  system.stateVersion = "24.05";
}
