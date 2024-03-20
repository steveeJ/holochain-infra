{
  # System independent arguments.
  self,
  lib,
  ...
}: {
  flake = {
    # system independent outputs like nixosModules, nixosConfigurations, etc.

    # nixosConfigurations.example-host = ...
    overlays.coturn = _final: previous: {
      coturn = previous.coturn.overrideAttrs (
        _super: {
          # coturn for NixOS needs to be built without libev_ok, otherwise acme-redirect won't work
          LIBEV_OK = "0";
          meta.platforms = lib.platforms.linux;
        }
      );
    };

    nixosModules.holochain-turn-server = {
      config,
      lib,
      ...
    }: let
      cfg = config.services.holochain-turn-server;
    in {
      options.services.holochain-turn-server = {
        enable = lib.mkEnableOption "holochain turn server";
        url = lib.mkOption {
          description = "publicly visible url for the turn server";
          type = lib.types.str;
        };
        turn-cert-dir = lib.mkOption {
          description = "directory where fullchain.pem and key.pem are expected to exist";
          type = lib.types.str;
          default = config.security.acme.certs.${cfg.url}.directory;
        };
        address = lib.mkOption {
          description = "address coturn should listen on";
          type = lib.types.str;
        };

        nginx-http-port = lib.mkOption {
          description = "port for nginx to listen on for answering ACME challenges";
          type = lib.types.int;
          # skipping 81 because it's the default coturn alternative http port
          default = 82;
        };

        coturn-min-port = lib.mkOption {
          description = "lower port for coturn's range";
          type = lib.types.int;
          default = 20000;
        };

        coturn-max-port = lib.mkOption {
          description = "upper port for coturn's range";
          type = lib.types.int;
          default = 65535; # which is default but here listing explicitly
        };

        verbose = lib.mkEnableOption "verbose logging";

        acme-redirect = lib.mkOption {
          description = "value passed to acme-redirect configuration option";
          type = lib.types.str;
          default = "http://acme-${cfg.url}/.well-known/acme-challenge/";
        };

        username = lib.mkOption {
          description = "user for establishing turn connections to coturn";
          type = lib.types.str;
          default = "test";
        };

        credential = lib.mkOption {
          description = "credential for establishing turn connections to coturn";
          type = lib.types.str;
          default = "test";
        };

        extraCoturnAttrs = lib.mkOption {
          description = "extra attributes assigned to services.coturn";
          type = lib.types.attrs;
          default = {};
        };
      };

      config = lib.mkIf cfg.enable {
        nixpkgs.overlays = [self.overlays.coturn];

        networking.firewall.allowedTCPPorts = [
          80
          443
          9641 # prometheus

          cfg.nginx-http-port
        ];
        networking.firewall.allowedUDPPorts = [
          80
          443
          9641 # prometheus
        ];
        networking.firewall.allowedUDPPortRanges = [
          {
            from = cfg.coturn-min-port;
            to = cfg.coturn-max-port;
          }
        ];

        services.coturn =
          {
            enable = true;
            listening-port = 80;
            tls-listening-port = 443;
            listening-ips = [cfg.address];
            lt-cred-mech = true; # Use long-term credential mechanism.
            realm = cfg.url;
            cert = "${cfg.turn-cert-dir}/fullchain.pem";
            pkey = "${cfg.turn-cert-dir}/key.pem";
            no-cli = false;
            min-port = cfg.coturn-min-port;
            max-port = cfg.coturn-max-port;
            extraConfig =
              ''
                no-software-attribute
                no-multicast-peers
                no-tlsv1
                no-tlsv1_1
                user=${cfg.username}:${cfg.credential}
                prometheus
              ''
              + lib.strings.optionalString cfg.verbose ''
                verbose
              ''
              + lib.strings.optionalString (cfg.acme-redirect != null) ''
                acme-redirect=${cfg.acme-redirect}
              '';
          }
          // cfg.extraCoturnAttrs;

        systemd.services.coturn.serviceConfig = {
          LimitNOFILESoft = 10000;
        };

        # Add turnserver user to nginx group, because turnserver needs to have access to TLS certs from /var/lib/acme/
        users.groups.nginx.members = ["turnserver"];

        services.nginx = {
          enable = true;

          # the sole purpose of nginx here is TLS certificate renewal from letsencrypt
          # coturn redirects ACME, i.e. HTTP GET requests matching '^/.well-known/acme-challenge/(.*)'
          # to acme-turn.holo.host, which is intercepted by a reverse-proxy and redirected to port ${cfg.nginx-http-port} on this host
          virtualHosts."${cfg.url}" = {
            listen = [
              {
                addr = "${cfg.address}";
                port = cfg.nginx-http-port;
                ssl = false;
              }
            ];
            enableACME = true;
            serverName = cfg.url;
          };
        };

        security.acme = {
          acceptTerms = true;
          defaults = {
            email = "acme@holo.host";
          };

          # after certificate renewal by acme coturn.service needs to reload this new cert, too
          # see https://github.com/NixOS/nixpkgs/blob/nixos-23.05/nixos/modules/security/acme/default.nix#L322
          certs."${cfg.url}".reloadServices = ["coturn"];

          # staging server has higher retry limits
          # certs."${cfg.url}".server = "https://acme-staging-v02.api.letsencrypt.org/directory";
        };
      };
    };
  };
}
