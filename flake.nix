{
  description = "The new, performant, and simplified version of Holochain on Rust (sometimes called Holochain RSM for Refactored State Model) ";

  inputs = {
    nixpkgs = {url = "github:nixos/nixpkgs/release-23.05";};
    nixpkgsGithubActionRunners = {url = "github:nixos/nixpkgs/nixos-unstable";};
    nixpkgsUnstable = {url = "github:nixos/nixpkgs/nixos-unstable";};

    disko.url = "github:nix-community/disko";
    disko.inputs.nixpkgs.follows = "nixpkgs";

    srvos.url = "github:numtide/srvos";
    srvos.inputs.nixpkgs.follows = "nixpkgs";

    nixos-anywhere.url = "github:numtide/nixos-anywhere";
    nixos-anywhere.inputs.nixpkgs.follows = "nixpkgs";

    # nix darwin
    darwin.url = "github:steveeJ-forks/nix-darwin/pr_gc_interval";
    darwin.inputs.nixpkgs.follows = "nixpkgs";

    # home manager
    home-manager.url = "github:nix-community/home-manager/release-23.05";
    home-manager.inputs.nixpkgs.follows = "nixpkgs";

    # secret management
    sops-nix.url = "github:Mic92/sops-nix";
    sops-nix.inputs.nixpkgs.follows = "nixpkgs";

    keys_steveej = {
      url = "https://github.com/steveej.keys";
      flake = false;
    };
    keys_jost-s = {
      url = "https://github.com/jost-s.keys";
      flake = false;
    };
    # hash mismatch
    # keys_maackle = {
    #   url = "https://github.com/maackle.keys";
    #   flake = false;
    # };
    keys_neonphog = {
      url = "https://github.com/neonphog.keys";
      flake = false;
    };
    # TODO: re-enable once the change is verified
    # keys_thedavidmeister = {
    #   url = "https://github.com/thedavidmeister.keys";
    #   flake = false;
    # };
    keys_thetasinner = {
      url = "https://github.com/ThetaSinner.keys";
      flake = false;
    };

    # NAR mismatch as of 2023/07/21
    # keys_zippy = {
    #   url = "https://github.com/zippy.keys";
    #   flake = false;
    # };
    keys_artbrock = {
      url = "https://github.com/artbrock.keys";
      flake = false;
    };

    cachix_for_watch_store.url = github:cachix/cachix/v1.5;
  };

  outputs = inputs @ {
    self,
    flake-parts,
    ...
  }:
    flake-parts.lib.mkFlake {inherit inputs;} {
      # auto import all nix code from `./modules`
      imports =
        map (m: "${./.}/modules/flake-parts/${m}")
        (builtins.attrNames (builtins.readDir ./modules/flake-parts));

      systems = ["aarch64-darwin" "x86_64-darwin" "x86_64-linux"];

      perSystem = {
        config,
        self',
        inputs',
        pkgs,
        ...
      }: {
        # Per-system attributes can be defined here. The self' and inputs'
        # module parameters provide easy access to attributes of the same
        # system.
        devShells.default = pkgs.mkShell {
          packages = [
            pkgs.yq-go

            inputs'.nixos-anywhere.packages.default

            inputs'.sops-nix.packages.default
            pkgs.ssh-to-age
            pkgs.age
            pkgs.age-plugin-yubikey
            pkgs.sops

            self'.packages.nomad
          ];

          NOMAD_ADDR = "https://${self.nixosConfigurations.dweb-reverse-tls-proxy.config.hostName}:4646";
          NOMAD_CACERT = "./secrets/nomad/admin/nomad-agent-ca.pem";
          NOMAD_CLIENT_CERT = ./secrets/nomad/cli/global-cli-nomad.pem;

          shellHook = ''
            set -x
            REPO_SECRETS_DIR="''${HOME:?}/.holochain-infra-secrets"
            mkdir -p ''${REPO_SECRETS_DIR}
            chmod 700 ''${REPO_SECRETS_DIR}
            export NOMAD_CLIENT_KEY="''${REPO_SECRETS_DIR}/global-cli-nomad-key";
            sops -d secrets/nomad/cli/keys.yaml | yq '.global-cli-nomad-key' > ''${NOMAD_CLIENT_KEY:?}
          '';
        };

        packages = {
          nomad = inputs'.nixpkgsUnstable.legacyPackages.nomad_1_5;
        };
      };
      flake = {
        # The usual flake attributes can be defined here, including system-
        # agnostic ones like nixosModule and system-enumerating ones, although
        # those are more easily expressed in perSystem.
      };
    };
}
