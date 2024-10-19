{
  inputs = {
    flake-utils.url = "github:numtide/flake-utils";
    flake-compat.url = "github:edolstra/flake-compat";

    nixpkgs.follows = "nixpkgs-24-05";
    nixpkgs-23-11 = {
      url = "github:nixos/nixpkgs/nixos-23.11";
    };
    nixpkgs-24-05 = {
      url = "github:nixos/nixpkgs/nixos-24.05";
    };
    nixpkgsNix.follows = "nixpkgs-24-05";
    nixpkgsGithubActionRunners = {
      url = "github:nixos/nixpkgs/nixos-unstable";
    };
    nixpkgsUnstable = {
      url = "github:nixos/nixpkgs/nixos-unstable";
    };
    nixpkgsMaster = {
      url = "github:nixos/nixpkgs/master";
    };

    disko.url = "github:nix-community/disko";
    disko.inputs.nixpkgs.follows = "nixpkgs";

    srvos.url = "github:numtide/srvos";
    srvos.inputs.nixpkgs.follows = "nixpkgs";

    nixos-anywhere.url = "github:numtide/nixos-anywhere";
    nixos-anywhere.inputs.nixpkgs.follows = "nixpkgs";
    nixos-anywhere.inputs.disko.follows = "disko";
    nixos-anywhere.inputs.treefmt-nix.follows = "treefmt-nix";
    nixos-anywhere.inputs.flake-parts.follows = "flake-parts";

    microvm.url = "github:astro/microvm.nix";
    microvm.inputs.nixpkgs.follows = "nixpkgs";
    microvm.inputs.flake-utils.follows = "flake-utils";

    # nix darwin
    darwin.url = "github:LnL7/nix-darwin";
    darwin.inputs.nixpkgs.follows = "nixpkgs";

    # home manager
    home-manager.url = "github:nix-community/home-manager/release-24.05";
    home-manager.inputs.nixpkgs.follows = "nixpkgs";

    # secret management
    sops-nix.url = "github:Mic92/sops-nix";
    sops-nix.inputs.nixpkgs.follows = "nixpkgs";
    sops-nix.inputs.nixpkgs-stable.follows = "";

    # have the latest rust version available
    craneNixpkgs = {
      url = "github:nixos/nixpkgs/nixos-unstable";
    };
    crane = {
      url = "github:ipetkov/crane";
    };

    keys_steveej = {
      url = "https://github.com/steveej.keys";
      flake = false;
    };
    keys_jost-s = {
      url = "https://github.com/jost-s.keys";
      flake = false;
    };

    # hash mismatch 2024/02/29
    # keys_maackle = {
    #   url = "https://github.com/maackle.keys";
    #   flake = false;
    # };

    # hash mismatch 20230821
    # keys_neonphog = {
    #   url = "https://github.com/neonphog.keys";
    #   flake = false;
    # };

    # TODO: re-enable once the change is verified
    # keys_thedavidmeister = {
    #   url = "https://github.com/thedavidmeister.keys";
    #   flake = false;
    # };

    keys_thetasinner = {
      url = "https://github.com/ThetaSinner.keys";
      flake = false;
    };

    # hash mismatch 20240710
    # keys_zippy = {
    #   url = "https://github.com/zippy.keys";
    #   flake = false;
    # };

    keys_artbrock = {
      url = "https://github.com/artbrock.keys";
      flake = false;
    };

    keys_r-vdp = {
      url = "https://git.sr.ht/~r-vdp/nixos-config/blob/main/users/ramses/authorized_keys";
      flake = false;
    };

    cachix_for_watch_store = {
      url = "github:cachix/cachix/v1.5";
      inputs = {
        nixpkgs.follows = "nixpkgs";
        flake-compat.follows = "flake-compat";
        # Nix doesn't accept this, lix does...
        #devenv.inputs.pre-commit-hooks.follows = "pre-commit-hooks";
        #devenv.inputs.nixpkgs.follows = "nixpkgs";
      };
    };

    tx5.url = "github:holochain/tx5/tx5-signal-srv-v0.0.8-alpha";
    tx5.flake = false;
    sbd.url = "github:holochain/sbd/sbd-server-v0.0.4-alpha";
    sbd.flake = false;

    holochain-versions = {
      url = "github:holochain/holochain?dir=versions/weekly";
      inputs = {
        holochain.follows = "holochain";
      };
    };
    holochain = {
      url = "github:holochain/holochain";
      inputs = {
        versions.follows = "holochain-versions";
        flake-compat.follows = "flake-compat";
        flake-parts.follows = "flake-parts";
        rust-overlay.follows = "rust-overlay";
        pre-commit-hooks-nix.follows = "pre-commit-hooks";
      };
    };

    coturn = {
      flake = false;
      url = "github:steveej-forks/coturn/debug-cli-login";
    };

    nixos-generators = {
      url = "github:nix-community/nixos-generators";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs = {
        nixpkgs.follows = "nixpkgs";
      };
    };

    threefold-rfs = {
      url = "github:threefoldtech/rfs";
      inputs.nixpkgs.follows = "nixpkgs";
      inputs.crane.follows = "crane";
      inputs.flake-utils.follows = "flake-utils";
      inputs.rust-overlay.follows = "rust-overlay";
    };

    holoNixpkgs = {
      url = "https://hydra.holo.host/channel/custom/holo-nixpkgs/2112/holo-nixpkgs/nixexprs.tar.xz";
      inputs = {
        nixpkgs.follows = "nixpkgs";
        flake-utils.follows = "flake-utils";
        crane.follows = "crane";
        flake-compat.follows = "flake-compat";
        rust-overlay.follows = "rust-overlay";
        treefmt-nix.follows = "treefmt-nix";
        devshell.follows = "devshell";
        pre-commit-hooks.follows = "pre-commit-hooks";
      };
    };

    nixpkgsPulumi.url = "github:steveej-forks/nixpkgs/pulumi-version-bump";

    nixos-vscode-server = {
      url = "github:nix-community/nixos-vscode-server";
      inputs = {
        nixpkgs.follows = "nixpkgs";
        flake-utils.follows = "flake-utils";
      };
    };

    treefmt-nix = {
      url = "github:numtide/treefmt-nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    pre-commit-hooks = {
      url = "github:cachix/git-hooks.nix";
      inputs = {
        nixpkgs.follows = "nixpkgs";
        nixpkgs-stable.follows = "";
        flake-compat.follows = "flake-compat";
      };
    };

    devshell = {
      url = "github:numtide/devshell";
      inputs = {
        nixpkgs.follows = "nixpkgs";
      };
    };

    # do not forward 'nixpkgs' there as buildbot-nix uses custom buildbot patches
    buildbot-nix.url = "github:nix-community/buildbot-nix";
    buildbot-nix.inputs.nixpkgs.follows = "nixpkgsUnstable";
  };

  outputs =
    inputs@{ self, flake-parts, ... }:
    flake-parts.lib.mkFlake { inherit inputs; } {
      # auto import all nix code from `./modules`
      imports = map (
        name:
        let
          lib = inputs.nixpkgs.lib;
          partFile = "${./.}/modules/flake-parts/${name}";
          part = import partFile;
          # some of the parts are just a set, and in order to inject a new function argument we construct a function from them.
          partFn = if (!builtins.isFunction part) then _: part else part;
          # make the part name available to each part via the specialArgs mechanism.
          partFn' = args: (partFn (lib.recursiveUpdate args { self.specialArgs.partName = name; }));
        in
        partFn'
      ) (builtins.attrNames (builtins.readDir ./modules/flake-parts));

      systems = [
        "aarch64-darwin"
        "x86_64-darwin"
        "x86_64-linux"
        "aarch64-linux"
      ];

      perSystem =
        {
          config,
          self',
          inputs',
          pkgs,
          lib,
          system,
          ...
        }:
        let
          treefmtConfig = {
            projectRootFile = "flake.nix";
            programs = {
              nixfmt.enable = true;
              shellcheck.enable = true;
              shfmt.enable = true;
              prettier.enable = true;
            };
            settings = {
              global.excludes = [
                "*.layout.json"
                "secrets/*"
                "*.md"
                "*.mdx"
              ];
              formatter.prettier = {
                options = [
                  "--trailing-comma"
                  "all"
                ];
              };
            };
          };
          treefmtWrapper =
            # This custom command is needed to prevent a conflict between
            # --tree-root and --tree-root-file.
            # treefmt-nix sets --tree-root-file whilst treefmt gets --tree-root
            # from $PRJ_ROOT, which is set by numtide/devshell.
            pkgs.writeShellApplication {
              name = "treefmt";
              text = ''
                unset PRJ_ROOT
                ${lib.getExe (inputs.treefmt-nix.lib.mkWrapper pkgs treefmtConfig)} "$@"
              '';
            };
        in
        {
          # Per-system attributes can be defined here. The self' and inputs'
          # module parameters provide easy access to attributes of the same
          # system.
          formatter = treefmtWrapper;

          devShells.default =
            let
              nomadAddr = "https://${self.nixosConfigurations.dweb-reverse-tls-proxy.config.hostName}:4646";
              nomadCaCert = ./secrets/nomad/admin/nomad-agent-ca.pem;
              nomadClientCert = ./secrets/nomad/cli/global-cli-nomad.pem;

              pkgsPulumi = inputs'.nixpkgsPulumi.legacyPackages;
            in
            inputs.devshell.legacyPackages.${system}.mkShell {
              packages =
                [
                  treefmtWrapper

                  pkgs.yq-go

                  inputs'.nixos-anywhere.packages.default

                  inputs'.sops-nix.packages.default
                  pkgs.ssh-to-age
                  pkgs.age
                  pkgs.age-plugin-yubikey
                  pkgs.sops
                  (pkgs.writeShellScriptBin "sops-update-keys" ''
                    for file in $(egrep -lr '"?sops"?:') secrets; do sops updatekeys -y $file; done
                  '')

                  # self'.packages.nomad

                  (pkgs.writeShellScriptBin "nomad-ui-proxy" (
                    let
                      caddyfile = pkgs.writeText "caddyfile" ''
                        {
                          auto_https off
                          http_port 2016
                        }

                        localhost:2016 {
                          reverse_proxy ${nomadAddr} {
                            transport http {
                              tls_trusted_ca_certs ${nomadCaCert}
                              tls_client_auth ${nomadClientCert} {$NOMAD_CLIENT_KEY}
                            }
                          }
                        }
                      '';
                    in
                    ''
                      ${pkgs.caddy}/bin/caddy run --adapter caddyfile --config ${caddyfile}
                    ''
                  ))
                  pkgs.caddy

                  inputs'.threefold-rfs.packages.default
                  pkgs.minio-client

                  pkgs.jq
                  pkgsPulumi.pulumictl
                  (pkgsPulumi.pulumi.withPackages (
                    pulumiPackages: with pulumiPackages; [
                      pulumi-language-go
                      pulumi-command
                    ]
                  ))
                  pkgs.go_1_21
                ]
                ++ (
                  let
                    zosCmds = builtins.filter (pkg: null != (builtins.match "^zos-.*" pkg.name)) (
                      builtins.attrValues self'.packages
                    );
                  in
                  zosCmds
                  ++ (lib.lists.flatten (builtins.map (cmd: cmd.nativeBuildInputs or [ ]) zosCmds))
                  ++ (lib.lists.flatten (builtins.map (cmd: cmd.buildInputs or [ ]) zosCmds))
                  ++ (lib.lists.flatten (builtins.map (cmd: cmd.runtimeInputs or [ ]) zosCmds))
                )
                ++ self.checks.${system}.pre-commit-check.enabledPackages;

              env = [
                {
                  name = "NOMAD_ADDR";
                  value = nomadAddr;
                }
                {
                  name = "NOMAD_CACERT";
                  value = "${nomadCaCert}";
                }
                {
                  name = "NOMAD_CLIENT_CERT";
                  value = "${nomadClientCert}";
                }
              ];

              devshell.startup = {
                pre-commit.text = self.checks.${system}.pre-commit-check.shellHook;
                sops.text =
                  let
                    devMinioOsConfig = self.nixosConfigurations.x64-linux-dev-01.config;
                  in
                  ''
                    if sops -d secrets/nomad/cli/keys.yaml 2>&1 >/dev/null; then
                      REPO_SECRETS_DIR="''${HOME:?}/.holochain-infra-secrets"
                      mkdir -p ''${REPO_SECRETS_DIR}
                      chmod 700 ''${REPO_SECRETS_DIR}
                      export NOMAD_CLIENT_KEY="''${REPO_SECRETS_DIR}/global-cli-nomad-key";
                      sops -d secrets/nomad/cli/keys.yaml | yq '.global-cli-nomad-key' > ''${NOMAD_CLIENT_KEY:?}
                    fi
                  ''
                  + (
                    let
                      minioUserPass = ''''${MINIO_ROOT_USER}:''${MINIO_ROOT_PASSWORD}'';
                      minioDevHost = devMinioOsConfig.services.devMinio.s3Domain + ":443";
                      minioDevLocalHost = "127.0.0.1:${builtins.toString devMinioOsConfig.services.devMinio.listenPort}";
                      minioRegion = devMinioOsConfig.services.devMinio.region;
                    in
                    ''
                      if sops -d secrets/minio/server.yaml 2>&1 >/dev/null; then
                        source <(sops -d secrets/minio/server.yaml | yq '.minio_root_credentials')

                        export MC_HOST_devminio_local="http://${minioUserPass}@${minioDevLocalHost}";
                        export MC_HOST_devminio="https://${minioUserPass}@${minioDevHost}"

                        export RFS_HOST_devminio_region="${minioRegion}"
                        export RFS_HOST_devminio_local="s3://${minioUserPass}@${minioDevLocalHost}"
                        export RFS_HOST_devminio="s3s://${minioUserPass}@${minioDevHost}"
                      fi
                    ''
                  );
              };
            };

          packages =
            {
              # nomad = pkgs.nomad_1_6;

              nixos-anywhere = inputs'.nixos-anywhere.packages.default;
            }
            // (
              let
                mkOsConfigCheck =
                  osConfigs:
                  let
                    filteredBySystem = lib.filterAttrs (_: osConfig: (osConfig.pkgs.system == system)) osConfigs;
                    asStrings = lib.mapAttrsToList (
                      key: value:
                      builtins.trace "evaluating ${key} (${value.pkgs.system})..." "ln -s ${value.config.system.build.toplevel} $out/${key}"
                    ) filteredBySystem;
                  in
                  pkgs.stdenv.mkDerivation {
                    name = "check-osconfigurations";
                    phases = "installPhase";
                    installPhase = "mkdir $out;" + builtins.concatStringsSep "\n" asStrings;
                  };
              in
              {
                build-os-configurations =
                  if pkgs.stdenv.isLinux then
                    mkOsConfigCheck (
                      builtins.removeAttrs self.nixosConfigurations [
                        # too big for current CI structure and rarely used
                        "vm-nixcache"

                        # needs private repos
                        "tfgrid-hpos"
                        "tfgrid-hpos-base"
                      ]
                    )
                  else if pkgs.stdenv.isDarwin then
                    mkOsConfigCheck self.darwinConfigurations
                  else
                    throw "unexpected case";
              }
            );

          checks = {
            pre-commit-check = inputs.pre-commit-hooks.lib.${system}.run {
              src = ./.;
              hooks = {
                nil.enable = true;
                deadnix = {
                  enable = true;
                  settings = {
                    noLambdaPatternNames = true;
                  };
                };
                treefmt = {
                  enable = true;
                  package = treefmtWrapper;
                  pass_filenames = false;
                };
              };
            };

            inherit (self'.packages) build-os-configurations;
          };
        };
      flake = {
        # The usual flake attributes can be defined here, including system-
        # agnostic ones like nixosModule and system-enumerating ones, although
        # those are more easily expressed in perSystem.
      };
    };
}
