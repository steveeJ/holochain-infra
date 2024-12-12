{
  config,
  lib,
  inputs,
  self,
  pkgs,
  ...
}:
{
  imports = [
    inputs.disko.nixosModules.disko
    inputs.srvos.nixosModules.server
    inputs.srvos.nixosModules.mixins-terminfo
    inputs.srvos.nixosModules.hardware-hetzner-cloud

    inputs.sops-nix.nixosModules.sops

    self.nixosModules.holo-users
    ../../nixos/shared.nix
    ../../nixos/shared-nix-settings.nix

    self.nixosModules.shared-monitoring-clients
  ];

  passthru = {
    fqdn = "${config.passthru.hostName}.${config.passthru.domain}";
    hostName = "dweb-reverse-tls-proxy"; # Define your hostname.
    domain = config.passthru.infraDomain;
    infraDomain = "infra.holochain.org";
    primaryIpv4 = "5.78.43.185";
  };

  hostName = config.passthru.primaryIpv4;
  networking = {
    inherit (config.passthru) hostName domain;
  };

  nix.settings.max-jobs = 8;

  nix.settings.substituters = [ "https://holochain-ci.cachix.org" ];

  nix.settings.trusted-public-keys = [
    "holochain-ci.cachix.org-1:5IUSkZc0aoRS53rfkvH9Kid40NpyjwCMCzwRTXy+QN8="
  ];

  boot.loader.systemd-boot.enable = false;
  boot.loader.grub.efiSupport = true;
  boot.loader.grub.efiInstallAsRemovable = false;

  disko.devices.disk.sda = {
    device = "/dev/sda";
    type = "disk";
    content = {
      type = "gpt";
      partitions = {
        boot = {
          size = "1M";
          type = "EF02"; # for grub MBR
        };
        ESP = {
          type = "EF00";
          size = "1G";
          content = {
            type = "filesystem";
            format = "vfat";
            mountpoint = "/boot";
          };
        };
        root = {
          size = "100%";
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
  };

  system.stateVersion = "23.11";

  networking.firewall.allowedTCPPorts = [
    53
    80
    443
    8030
  ];

  networking.firewall.allowedUDPPorts = [ 53 ];

  ### BIND and ACME

  # FIXME: changes to the bind zone require a manual `systemctl restart bind`
  system.activationScripts.bind-zones.text = ''
    mkdir -p /etc/bind/zones
    chown named:named /etc/bind/zones
  '';

  environment.etc."bind/zones/${config.passthru.infraDomain}.zone" = {
    enable = true;
    user = "named";
    group = "named";
    mode = "0644";
    text = ''
      $ORIGIN .
      $TTL 60 ; 1 minute
      ${config.passthru.infraDomain} IN SOA ns1.${config.passthru.infraDomain}. admin.holochain.org. (
                                        2001062504 ; serial
                                        21600      ; refresh (6 hours)
                                        3600       ; retry (1 hour)
                                        604800     ; expire (1 week)
                                        86400      ; minimum (1 day)
                                      )

                              NS      ns1.${config.passthru.infraDomain}.
      $ORIGIN ${config.passthru.infraDomain}.
      ns1                                                      A       ${config.passthru.primaryIpv4}
      ${config.passthru.infraDomain}.                          A       ${config.passthru.primaryIpv4}

      *.${config.passthru.infraDomain}.                        CNAME   ${config.passthru.infraDomain}.

      testing.events.${config.passthru.infraDomain}.           A       127.0.0.1
      hackathons.events.${config.passthru.infraDomain}.        A       10.1.3.37
      hackathon.events.${config.passthru.infraDomain}.         A       10.1.3.37
      amsterdam2023.events.${config.passthru.infraDomain}.     A       10.1.3.187

      x64-linux-dev-01.dev.${config.passthru.infraDomain}.     A       ${self.nixosConfigurations.x64-linux-dev-01.config.passthru.primaryIpv4}
      s3.dev.${config.passthru.infraDomain}.                   A       ${self.nixosConfigurations.x64-linux-dev-01.config.passthru.primaryIpv4}
      s3-console.dev.${config.passthru.infraDomain}.           A       ${self.nixosConfigurations.x64-linux-dev-01.config.passthru.primaryIpv4}

      turn-0.${config.passthru.infraDomain}.                   A       ${self.nixosConfigurations.turn-0.config.services.holochain-turn-server.address}
      signal-0.${config.passthru.infraDomain}.                 A       ${self.nixosConfigurations.turn-0.config.services.tx5-signal-server.address}
      bootstrap-0.${config.passthru.infraDomain}.              A       ${self.nixosConfigurations.turn-0.config.services.kitsune-bootstrap.address}

      turn-1.${config.passthru.infraDomain}.                   A       ${self.nixosConfigurations.turn-1.config.services.holochain-turn-server.address}
      signal-1.${config.passthru.infraDomain}.                 A       ${self.nixosConfigurations.turn-1.config.services.tx5-signal-server.address}
      bootstrap-1.${config.passthru.infraDomain}.              A       ${self.nixosConfigurations.turn-1.config.services.kitsune-bootstrap.address}

      turn-2.${config.passthru.infraDomain}.                   A       ${self.nixosConfigurations.turn-2.config.services.holochain-turn-server.address}
      signal-2.${config.passthru.infraDomain}.                 A       ${self.nixosConfigurations.turn-2.config.services.tx5-signal-server.address}
      bootstrap-2.${config.passthru.infraDomain}.              A       ${self.nixosConfigurations.turn-2.config.services.kitsune-bootstrap.address}

      monitoring-0.${config.passthru.infraDomain}.             A       ${self.nixosConfigurations.monitoring-0.config.passthru.primaryIpv4}
      monitoring-0.${config.passthru.infraDomain}.             AAAA    ${self.nixosConfigurations.monitoring-0.config.passthru.primaryIpv6}
      monitoring.${config.passthru.infraDomain}.               CNAME   monitoring-0.${config.passthru.infraDomain}.

      buildbot-nix-0.${config.passthru.infraDomain}.           A       ${self.nixosConfigurations.buildbot-nix-0.config.passthru.primaryIpv4}
      buildbot-nix-0.${config.passthru.infraDomain}.           AAAA    ${self.nixosConfigurations.buildbot-nix-0.config.passthru.primaryIpv6}

      linux-builder-01.${config.passthru.infraDomain}.         A       ${self.nixosConfigurations.linux-builder-01.config.passthru.primaryIpv4}
      linux-builder-2.${config.passthru.infraDomain}.          A       ${self.nixosConfigurations.linux-builder-2.config.passthru.primaryIpv4}
      aarch64-linux-builder-0.${config.passthru.infraDomain}.  A       ${self.nixosConfigurations.aarch64-linux-builder-0.config.passthru.primaryIpv4}
    '';
  };

  services.bind = {
    enable = true;
    extraConfig = ''
      include "/var/lib/secrets/*-dnskeys.conf";
    '';
    zones = [
      {
        name = config.passthru.infraDomain;
        allowQuery = [ "any" ];
        file = "/etc/bind/zones/${config.passthru.infraDomain}.zone";
        master = true;
        extraConfig = "allow-update { key rfc2136key.${config.passthru.infraDomain}.; };";
      }
    ];
  };

  # Reload the bind config when the zone file changed
  systemd.services.bind.reloadTriggers = [
    config.environment.etc."bind/zones/${config.passthru.infraDomain}.zone".source
  ];

  security.acme = {
    acceptTerms = true;
    defaults = {
      email = "admin@holochain.org";
    };

    certs."${config.passthru.infraDomain}" = {
      domain = "*.${config.passthru.infraDomain}";
      extraDomainNames = [ "*.cachix.${config.passthru.infraDomain}" ];
      dnsProvider = "rfc2136";
      credentialsFile = "/var/lib/secrets/${config.passthru.infraDomain}-dnskeys.secret";
      # We don't need to wait for propagation since this is a local DNS server
      dnsPropagationCheck = false;
    };

    # can be used for debugging
    # preliminarySelfsigned = true;
    # server = "https://acme-staging-v02.api.letsencrypt.org/directory";
  };

  systemd.services.dns-rfc2136-2-conf =
    let
      dnskeysConfPath = "/var/lib/secrets/${config.passthru.infraDomain}-dnskeys.conf";
      dnskeysSecretPath = "/var/lib/secrets/${config.passthru.infraDomain}-dnskeys.secret";
    in
    {
      requiredBy = [
        "acme-${config.passthru.infraDomain}.service"
        "bind.service"
      ];
      before = [
        "acme-${config.passthru.infraDomain}.service"
        "bind.service"
      ];
      unitConfig = {
        ConditionPathExists = "!${dnskeysConfPath}";
      };
      serviceConfig = {
        Type = "oneshot";
        UMask = 77;
      };
      path = [ pkgs.bind ];
      script = ''
        mkdir -p /var/lib/secrets
        chmod 755 /var/lib/secrets
        tsig-keygen rfc2136key.${config.passthru.infraDomain} > ${dnskeysConfPath}
        chown named:root ${dnskeysConfPath}
        chmod 400 ${dnskeysConfPath}

        # extract secret value from the dnskeys.conf
        while read x y; do if [ "$x" = "secret" ]; then secret="''${y:1:''${#y}-3}"; fi; done < ${dnskeysConfPath}

        cat > ${dnskeysSecretPath} << EOF
        RFC2136_NAMESERVER='127.0.0.1:53'
        RFC2136_TSIG_ALGORITHM='hmac-sha256.'
        RFC2136_TSIG_KEY='rfc2136key.${config.passthru.infraDomain}'
        RFC2136_TSIG_SECRET='$secret'
        EOF
        chmod 400 ${dnskeysSecretPath}
      '';
    };

  ### Caddy
  users.users.caddy.extraGroups = [ "acme" ];
  services.caddy.enable = true;
  services.caddy.virtualHosts = {
    "steveej.${config.passthru.infraDomain}:443" = {
      useACMEHost = config.passthru.infraDomain;
      extraConfig = ''
        reverse_proxy http://172.24.154.109:80 {
          transport http {
            keepalive 1d
          }
        }
      '';
    };

    # zippy 1 / emerge-3
    "dweb1.${config.passthru.infraDomain}:443" = {
      useACMEHost = config.passthru.infraDomain;
      extraConfig = ''
        reverse_proxy http://172.24.135.11:80 {
          transport http {
            keepalive 1d
          }
        }
      '';
    };

    # stub for redirecting the holochain-ci cachix to a DNS we're in control of.
    # the use-case is that we can now override this DNS at local events and insert a transparent nix cache
    "cachix.${config.passthru.infraDomain}:443" = {
      useACMEHost = config.passthru.infraDomain;
      extraConfig = ''
        respond /api/v1/cache/holochain-ci `{"githubUsername":"","isPublic":true,"name":"holochain-ci","permission":"Read","preferredCompressionMethod":"ZSTD","publicSigningKeys":["holochain-ci.cachix.org-1:5IUSkZc0aoRS53rfkvH9Kid40NpyjwCMCzwRTXy+QN8="],"uri":"https://holochain-ci.cachix.infra.holochain.org"}`

        redir / https://cachix.org{uri}
      '';
    };

    "holochain-ci.cachix.${config.passthru.infraDomain}:443" = {
      useACMEHost = config.passthru.infraDomain;
      extraConfig = ''
        redir https://holochain-ci.cachix.org{uri}
        # reverse_proxy https://holochain-ci.cachix.org
      '';
    };

    "acme-turn-0.${config.passthru.infraDomain}:80" = {
      extraConfig = ''
        reverse_proxy http://turn-0.${config.passthru.infraDomain}:${builtins.toString self.nixosConfigurations.turn-0.config.services.holochain-turn-server.nginx-http-port}
      '';
    };

    "acme-turn-1.${config.passthru.infraDomain}:80" = {
      extraConfig = ''
        reverse_proxy http://turn-1.${config.passthru.infraDomain}:${builtins.toString self.nixosConfigurations.turn-1.config.services.holochain-turn-server.nginx-http-port}
      '';
    };

    "acme-turn-2.${config.passthru.infraDomain}:80" = {
      extraConfig = ''
        reverse_proxy http://turn-2.${config.passthru.infraDomain}:${builtins.toString self.nixosConfigurations.turn-2.config.services.holochain-turn-server.nginx-http-port}
      '';
    };
  };
}
