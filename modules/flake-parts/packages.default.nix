{
  # System independent arguments.
  self,
  inputs,
  lib,
  ...
}:
{
  perSystem =
    {
      # Arguments specific to the `perSystem` context.
      pkgs,
      self',
      ...
    }:
    {
      # system specific outputs like, apps, checks, packages

      packages =
        let
          mkPingBuildmachines =
            { builderName }:
            pkgs.writeShellApplication {
              name = "${builderName}-ping-buildmachines";
              text = builtins.concatStringsSep "\n" (
                builtins.map
                  (
                    builder:
                    let
                      sshTarget = "${builder.sshUser}@${builder.hostName}";
                    in
                    ''
                      # 255 is the timeout exit status which is the best we can check for here. a hard error would be expected to show up sooner and have a different exit status.
                      nix run .#ssh-${builderName} "ssh-keygen -R ${builder.hostName}; timeout --preserve-status 5s ssh -o StrictHostKeyChecking=accept-new ${sshTarget}; if [ \$? -ne 255 ]; then exit 1; fi; nix store info --store ssh-ng://${sshTarget}"
                    ''
                  )
                  (
                    builtins.filter (
                      builder: builder.maxJobs > 0
                    ) self.nixosConfigurations.${builderName}.config.nix.buildMachines
                  )
              );
            };
        in
        {
          reverse-proxy-nix-cache = pkgs.writeShellScriptBin "reverse-proxy-nix-cache" ''
            sudo ${pkgs.caddy}/bin/caddy reverse-proxy --from :80 --to :5000
          '';

          turn-readiness-check = pkgs.writeShellApplication {
            name = "turn-readiness-check";
            runtimeInputs = [ self'.packages.tx5 ];
            text =
              ''
                set -e
              ''
              + builtins.concatStringsSep "\n" (
                builtins.map
                  (name: ''
                    echo "### checking ${name}... ###"
                    set -x
                    turn-stress ${name}.infra.holochain.org 443 test test
                    turn_doctor wss://${self.nixosConfigurations.${name}.config.services.tx5-signal-server.url}
                    set +x
                    echo "### checking ${name}: success ###"
                  '')
                  (
                    builtins.filter (name: (builtins.match "turn-[0-9]+" name) != null) (
                      builtins.attrNames self.nixosConfigurations
                    )
                  )
              )
              + ''
                echo success
              '';
          };

          linux-builder-01-ping-buildmachines = mkPingBuildmachines { builderName = "linux-builder-01"; };
        };
    };

  flake = {
    # system independent outputs like nixosModules, nixosConfigurations, etc.

    # nixosConfigurations.example-host = ...
  };
}
