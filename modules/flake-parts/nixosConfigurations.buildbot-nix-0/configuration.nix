{
  config,
  inputs,
  self,
  pkgs,
  lib,
  ...
}:
# Hetzner AX162-R #2497582
# UEFI - factory
{
  imports = [
    inputs.disko.nixosModules.disko
    inputs.srvos.nixosModules.server
    inputs.srvos.nixosModules.hardware-hetzner-online-amd
    inputs.srvos.nixosModules.roles-nix-remote-builder
    self.nixosModules.holo-users
    self.nixosModules.nix-build-distributor

    inputs.sops-nix.nixosModules.sops

    ../../nixos/shared.nix
    ../../nixos/shared-nix-settings.nix
    ../../nixos/shared-linux.nix

    self.nixosModules.shared-monitoring-clients

    inputs.buildbot-nix.nixosModules.buildbot-master
    inputs.buildbot-nix.nixosModules.buildbot-worker

  ];

  system.stateVersion = "24.05";

  passthru = {
    fqdn = "${config.passthru.hostName}.${config.passthru.domain}";

    domain = self.specialArgs.infraDomain;
    hostName = "buildbot-nix-0";

    primaryIpv4 = "65.109.100.254";
    primaryIpv6 = "2a01:4f9:3080:25e7::1/64";

    buildbot-nix = {
      appFqdn = "buildbot-nix-0.${config.passthru.domain}";
      appId = 1008744;
      oauthId = "Iv23liqmAiBw8ab9EF61";
      topic = "holo-chain-buildbot-nix-0";
    };

    buildbot-secrets = {
      # NOTE: for security reasons this secret is kept out of the public repo
      "cacheHoloHost2secret" = "/var/lib/secrets/cache.holo.host-2/secret";
      "awsSharedCredentialsFile" = config.sops.secrets.holo-host-aws-shared-credentials.path;
    };
  };

  networking = {
    inherit (config.passthru) hostName domain;
  };
  hostName = config.passthru.primaryIpv4;

  nix.settings.max-jobs = 48;

  boot.loader.grub = {
    enable = true;
    efiSupport = true;
    efiInstallAsRemovable = true;
    devices = [ "nodev" ];
  };
  boot.loader.efi.canTouchEfiVariables = false;
  boot.kernelPackages = pkgs.linuxPackages_latest;

  systemd.network.networks."10-uplink".networkConfig.Address = config.passthru.primaryIpv6;

  disko.devices =
    let
      disk = id: {
        type = "disk";
        device = "/dev/nvme${id}n1";
        content = {
          type = "gpt";
          partitions = {
            ESP = {
              priority = 100;
              # Hetzner
              start = "2M";
              size = "500M";
              # Hetzner's Debian installation was using "EFI System" as the partition code for the ESP mdadm raid1 members.
              # so far _this_ is not working, however it did for Hetzner.
              type = "EF00";
              content = {
                type = "mdraid";
                name = "esp";
              };
            };

            # boot = {
            #   priority = 101;
            #   size = "100%";
            #   content = {
            #     type = "mdraid";
            #     name = "boot";
            #   };
            # };

            rootfs = {
              size = "100%";
              content = {
                type = "mdraid";
                name = "rootfs";
              };
            };
          };
        };
      };
    in
    {
      disk = {
        sda = disk "0";
        sdb = disk "1";
      };

      mdadm = {
        esp = {
          type = "mdadm";
          level = 1;
          metadata = "1.0";
          content = {
            type = "filesystem";
            # hetzner
            format = "vfat";
            extraArgs = [
              "-F"
              "16"
            ];
            # FIXME: it should be possible to use /boot/efi here and leave /boot on the btrfs
            mountpoint = "/boot";
            mountOptions = [ "umask=0077" ];
          };
        };

        # boot = {
        #   type = "mdadm";
        #   level = 1;
        #   content = {
        #     type = "filesystem";
        #     format = "ext3";
        #     mountpoint = "/boot";
        #   };
        # };

        rootfs = {
          type = "mdadm";
          level = 0;
          content = {
            type = "btrfs";
            extraArgs = [ "-f" ]; # Override existing partition
            subvolumes = {
              # Subvolume name is different from mountpoint
              "/rootfs" = {
                mountpoint = "/";
              };
              "/nix" = {
                mountOptions = [ "noatime" ];
                mountpoint = "/nix";
              };
            };
          };
        };
      };
    };

  roles.nix-remote-builder.schedulerPublicKeys = [
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINQ22z5rDdCLYH+MEoEt+tXJXTJqoeZNqvJl2n4aB+Kn steveej@steveej-x13s"
  ];

  security.acme = {
    acceptTerms = true;
    defaults = {
      email = "postmaster@holochain.org";
    };
  };

  networking.firewall.allowedTCPPorts = [
    80
    443
  ];

  services.nginx.virtualHosts."${config.passthru.buildbot-nix.appFqdn}" = {
    enableACME = true;
    forceSSL = true;
  };

  sops.defaultSopsFile = self + "/secrets/${config.networking.hostName}/secrets.yaml";

  sops.secrets.buildbot-github-oauth-secret = { };
  sops.secrets.buildbot-github-app-secret-key = { };
  sops.secrets.buildbot-github-webhook-secret = { };
  sops.secrets.buildbot-nix-workers = { };
  # sops.secrets.cachix-auth-token = {};

  systemd.services.buildbot-master.serviceConfig.LoadCredential = builtins.map (
    kv: "${kv.name}:${kv.value}"
  ) (lib.attrsets.attrsToList config.passthru.buildbot-secrets);
  services.buildbot-nix.master = {
    enable = true;
    admins = [
      "steveej"
      "evangineer"
      "r-vdp"
    ];
    buildSystems = [
      "x86_64-linux"
      "aarch64-linux"
      "x86_64-darwin"
      "aarch64-darwin"
    ];
    domain = config.passthru.buildbot-nix.appFqdn;
    outputsPath = "/var/www/buildbot/nix-outputs/";
    evalMaxMemorySize = 6 * 1024;
    evalWorkerCount = 8;
    jobReportLimit = 0;
    workersFile = config.sops.secrets.buildbot-nix-workers.path;
    # cachix = {
    #   enable = true;
    #   name = "holochain-infra";
    #   auth.authToken.file = config.sops.secrets.cachix-auth-token.path;
    # };
    github = {
      authType.app = {
        id = config.passthru.buildbot-nix.appId;
        secretKeyFile = config.sops.secrets.buildbot-github-app-secret-key.path;
      };
      webhookSecretFile = config.sops.secrets.buildbot-github-webhook-secret.path;
      # this is a client secret
      oauthSecretFile = config.sops.secrets.buildbot-github-oauth-secret.path;
      # this is displayed in the app as "Client ID"
      inherit (config.passthru.buildbot-nix) oauthId topic;
    };

    postBuildSteps =
      let
        commonEnvironment =
          let
            props = lib.attrsets.genAttrs [
              "attr"
              "basename"
              "branch"
              "builddir"
              "builderid"
              "buildername"
              "buildnumber"
              "cacheStatus"
              "codebase"
              "drv_path"
              "event"
              "github.base.sha"
              "github.head.sha"
              "out_path"
              "owners"
              "project"
              "projectid"
              "projectname"
              "pullrequesturl"
              "repository"
              "revision"
              "scheduler"
              "status_name"
              "system"
              "virtual_builder_name"
              "virtual_builder_tags"
              "workername"
            ] (name: self.inputs.buildbot-nix.lib.interpolate "%(prop:${name})s");
            props' = lib.attrsets.mapAttrs' (name: value: lib.nameValuePair "PROP_${name}" value) props;
          in
          props';

      in
      [
        {
          /*
            TODO(observe): verify any of these aren't required

            ```nix
            binary_cache_public_uri = https://cache.holo.host
            log_prefix = https://cache.holo.host/
            server_store_uri = https://cache.holo.host?local-nar-cache=/var/cache/hydra/nar-cache
            upload_logs_to_binary_cache = true
            ```
          */
          name = "sign-and-upload";
          environment =
            commonEnvironment
            # verified with
            # nix-repl> (builtins.elemAt nixosConfigurations.buildbot-nix-0.config.services.buildbot-nix.master.postBuildSteps 1).environment
            // builtins.listToAttrs (
              builtins.map (
                name:
                lib.attrsets.nameValuePair "SECRET_${name}" (
                  self.inputs.buildbot-nix.lib.interpolate "%(secret:${name})s"
                )
              ) (builtins.attrNames config.passthru.buildbot-secrets)
            );
          command = [ (lib.getExe' self.packages.${pkgs.system}.postbuildstepper "postbuildstepper") ];
        }

      ];
  };

  # magic_rb:
  # If you dont pin it, then itll reset your db when it updates
  # Happened to me, as in the default config uses /var/lib/postgresql/{version}
  services.postgresql.package = pkgs.postgresql_15;

  sops.secrets.buildbot-nix-worker-password = { };
  services.buildbot-nix.worker = {
    enable = true;
    workerPasswordFile = config.sops.secrets.buildbot-nix-worker-password.path;
  };
  nix.settings.system-features = [
    "kvm"
    "nixos-test"
    "big-parallel"
  ];

  sops.secrets.holo-host-github-environment-secrets = { };
  sops.secrets.holo-host-aws-shared-credentials = { };
  systemd.services.nix-daemon.serviceConfig = {
    EnvironmentFile = [ config.sops.secrets.holo-host-github-environment-secrets.path ];
  };
}
