{
  partName,
  self,
  inputs,
  config,
  pkgs,
  ...
}:
{
  services.prometheus.exporters.node = {
    enable = true;
    enabledCollectors = [
      "systemd"
      "processes"
      "os"
    ];
    openFirewall = false;
  };

  imports = [ ];

  sops.secrets = {
    prometheus_remote_write_password = {
      sopsFile = self + "/secrets/monitoring-clients/secrets.yaml";
    };
  };

  systemd.services.alloy.serviceConfig = {
    StateDirectory = "alloy";
    LoadCredential = [
      "prometheus_remote_write_password:${config.sops.secrets.prometheus_remote_write_password.path}"
    ];
  };

  services.alloy = {
    enable = true;
    package = inputs.nixpkgsUnstable.legacyPackages.${pkgs.stdenv.system}.grafana-alloy;
    configPath =
      let
        configAlloy = pkgs.writeText "config.alloy" ''
          prometheus.scrape "node_static" {
            job_name = "node-static"

            scheme = "http"
            targets = [
              {
                "__address__" = "[::1]:${builtins.toString config.services.prometheus.exporters.node.port}",
                "instance" = "${config.passthru.fqdn}",
              },
            ]

            forward_to = [prometheus.remote_write.monitoring_0.receiver]

            scrape_interval = "10s"
          }

          prometheus.remote_write "monitoring_0" {
            endpoint {
              url = "https://${self.nixosConfigurations.monitoring-0.config.passthru.fqdn}/api/v1/write"
              basic_auth {
                username = "prometheus"
                password_file = sys.env("CREDENTIALS_DIRECTORY") + "/prometheus_remote_write_password"
              }
            }
          }
        '';
      in
      pkgs.runCommand "grafana-alloy.d" { } ''
        mkdir $out
        cp "${configAlloy}" "$out/config.alloy"
      '';
  };

  system.configurationRevision = self.sourceInfo.rev or (self.sourceInfo.dirtyRev or "dirty");
  system.image.id = partName;
  system.image.version = config.system.configurationRevision;
}
