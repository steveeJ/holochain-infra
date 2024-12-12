# TODO: refactor this into an actual nixos module

{
  self,
  config,
  pkgs,
  ...
}:

{
  networking.firewall.allowedTCPPorts = [
    4646
    4647
  ];

  # dynamic port ranges used by nomad services
  networking.firewall.allowedTCPPortRanges = [
    {
      from = 20000;
      to = 32000;
    }
  ];
  networking.firewall.allowedUDPPortRanges = [
    {
      from = 20000;
      to = 32000;
    }
  ];

  sops.secrets.global-server-nomad-key = {
    sopsFile = self + "/secrets/nomad/servers/keys.yaml";
    owner = config.users.extraUsers.nomad.name;
    group = config.users.groups.nomad.name;
  };

  services.nomad = {
    enable = true;
    package = pkgs.nomad_1_6;
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
      advertise = {
        http = config.hostName;
      };

      bind_addr = config.hostName;

      server = {
        enabled = true;
        bootstrap_expect = 1;

        server_join = {
          retry_join = [ config.hostName ];
        };
      };
      client = {
        enabled = true;

        node_class = "testing";

        meta = {
          inherit (pkgs.targetPlatform) system;

          features = builtins.concatStringsSep "," [
            "poc-1"
            "poc-2"
            "ipv4-public"
            "nix"
            "nixos"
          ];

          machine_type = "vps";
        };
      };
      plugin.raw_exec.config.enabled = true;

      tls = {
        http = true;
        rpc = true;
        ca_file = self + "/secrets/nomad/admin/nomad-agent-ca.pem";
        cert_file = self + "/secrets/nomad/servers/global-server-nomad.pem";
        key_file = config.sops.secrets.global-server-nomad-key.path;

        verify_server_hostname = true;
        verify_https_client = true;
      };
    };
  };

  users.extraUsers.nomad.isNormalUser = true;
  users.extraUsers.nomad.isSystemUser = false;
  users.extraUsers.nomad.group = "nomad";
  users.extraUsers.nomad.home = config.services.nomad.settings.data_dir;
  users.extraUsers.nomad.createHome = true;
  users.groups.nomad.members = [ "nomad" ];

  systemd.services.nomad.serviceConfig.User = "nomad";
  systemd.services.nomad.serviceConfig.Group = "nomad";
}
