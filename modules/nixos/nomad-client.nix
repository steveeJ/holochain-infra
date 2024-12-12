{
  self,
  lib,
  pkgs,
  config,
  ...
}:
let
  nomadEnvDir = "/var/lib/nomad-env";
  nomadEnvFile = "${nomadEnvDir}/nomad-extra.env";

  cfg = config.holochain-infra.nomad-client;
in
{
  options.holochain-infra.nomad-client = {
    enable = lib.mkEnableOption "the holochain-infra nomad service";
    machineType = lib.mkOption {
      description = "machine type string that is exposed via the agent metadata";
      type = lib.types.str;
      default = "unknown";
    };
  };

  config = lib.mkIf cfg.enable {
    nixpkgs.config.allowUnfreePredicate = pkg: builtins.elem (lib.getName pkg) [ "nomad" ];

    systemd.tmpfiles.rules = [ "d ${nomadEnvDir} 0750 root nomad -" ];

    systemd.services.nomad-env = {
      enable = true;
      path = [
        pkgs.coreutils
        pkgs.gawk
        pkgs.jq
        pkgs.iproute2
        pkgs.diffutils
        pkgs.nettools
      ];
      after = [ "zerotierone.service" ];
      requiredBy = [ "nomad.service" ];
      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
      };
      script = ''
        id
        pwd
        cat <<-EOF > ${nomadEnvFile}.new
        {
          "name": "$(hostname)",
          "client": {
            "meta": {
              "FLAKE_URL": "${
                let
                  inherit (self) sourceInfo;
                in
                sourceInfo.url or "unknown"
              }",
              "FLAKE_REV": "${
                let
                  inherit (self) sourceInfo;
                in
                sourceInfo.rev or (sourceInfo.dirtyRev or "unknown")
              }",
            }
          }
        }
        EOF
        echo new result:
        cat ${nomadEnvFile}.new
        if ! diff ${nomadEnvFile} ${nomadEnvFile}.new; then
          echo using new result
          mv ${nomadEnvFile}.new ${nomadEnvFile}
        else
          rm ${nomadEnvFile}.new
        fi
      '';
    };

    systemd.services.nomad-env-restarter = {
      enable = true;
      serviceConfig.Type = "oneshot";
      script = ''
        systemctl restart --force --now nomad-env.service
      '';
    };

    systemd.paths.nomad-env-watcher = {
      enable = true;
      requiredBy = [ "nomad-env.service" ];
      pathConfig = {
        PathChanged = [
          # these files might change when zerotier restarts or makes connections
          "/var/lib/zerotier-one/zerotier-one.pid"
          "/proc/net/route"
        ];
        Unit = "nomad-env-restarter.service";
      };
    };

    # sops.secrets.holochain-nomad-agent-ca = {
    #   owner = config.users.users.nomad.name;
    #   group = config.users.groups.nomad.name;
    # };
    # sops.secrets.holochain-global-nomad-client-cert = {
    #   owner = config.users.users.nomad.name;
    #   group = config.users.groups.nomad.name;
    # };

    sops.secrets.global-client-nomad-key = {
      sopsFile = self + "/secrets/nomad/client/keys.yaml";
      owner = config.users.users.nomad.name;
      group = config.users.groups.nomad.name;
    };

    services.nomad = {
      enable = true;
      package = pkgs.nomad_1_9;
      enableDocker = false;
      dropPrivileges = false;

      extraPackages = [
        pkgs.coreutils
        pkgs.nix
        pkgs.bash
        pkgs.gitFull
        pkgs.cacert
      ];

      settings = {
        server.enabled = false;

        client = {
          enabled = true;
          server_join = {
            retry_join = [ "infra.holochain.org" ];
            retry_interval = "60s";
          };

          node_class = "testing";

          meta = {
            inherit (pkgs.targetPlatform) system;

            features = builtins.concatStringsSep "," [
              "ipv4-nat"
              "nix"
              "nixos"
              "holoport"
            ];

            machine_type = cfg.machineType;
          };
        };

        tls = {
          http = true;
          rpc = true;
          ca_file = self + "/secrets/nomad/admin/nomad-agent-ca.pem";
          cert_file = self + "/secrets/nomad/client/global-client-nomad.pem";

          key_file = config.sops.secrets.global-client-nomad-key.path;

          verify_server_hostname = true;
          verify_https_client = true;
        };

        plugin.raw_exec.config.enabled = true;
      };

      extraSettingsPaths = [ nomadEnvFile ];
    };

    systemd.services.nomad-reloader = {
      enable = true;
      serviceConfig.Type = "oneshot";
      script = ''
        systemctl reload-or-restart --force --now nomad.service
      '';
    };

    systemd.paths.nomad-watcher = {
      enable = true;
      requires = [ "nomad-env.service" ];
      requiredBy = [ "nomad.service" ];
      pathConfig = {
        PathChanged = nomadEnvFile;
        Unit = "nomad-reloader.service";
      };
    };

    users = {
      users.nomad = {
        isNormalUser = true;
        isSystemUser = false;
        group = config.users.groups.nomad.name;
        home = config.services.nomad.settings.data_dir;
        createHome = true;
      };
      groups.nomad = { };
    };

    systemd.services.nomad = {
      serviceConfig = {
        User = config.users.users.nomad.name;
        Group = config.users.groups.nomad.name;
      };
    };

    security.sudo.extraRules = [
      # FIXME: the * causes syntax issues even though it's apparently supported by sudo
      # {
      #   users = ["nomad"];
      #   commands = [
      #     {
      #       # this command will allow switching to any branch
      #       command = "/run/current-system/sw/bin/nixos-rebuild --flake github:holochain/holochain-infra*";
      #       options = ["NOPASSWD"];
      #     }
      #   ];
      # }
    ];
  };
}
