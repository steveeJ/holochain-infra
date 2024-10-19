{
  # System independent arguments.
  lib,
  inputs,
  ...
}:
{
  perSystem =
    {
      # Arguments specific to the `perSystem` context.
      self',
      pkgs,
      ...
    }:
    {
      # system specific outputs like, apps, checks, packages

      packages =
        let
          system = pkgs.system;
          cranePkgs = inputs.craneNixpkgs.legacyPackages.${system};
          craneLib = inputs.crane.mkLib cranePkgs;

          tx5Args = {
            pname = "tx5";
            src = inputs.tx5;
            version = inputs.tx5.rev;
            cargoExtraArgs = "--examples --bins";
            nativeBuildInputs = [
              cranePkgs.perl
              cranePkgs.pkg-config
              cranePkgs.go
            ];

            doCheck = false;
          };
          tx5Deps = lib.makeOverridable craneLib.buildDepsOnly tx5Args;
        in
        {
          tx5 = lib.makeOverridable craneLib.buildPackage (tx5Args // { cargoArtifacts = tx5Deps; });

          tx5-signal-srv = self'.packages.tx5.override { cargoExtraArgs = "--bin tx5-signal-srv"; };
        };
    };
  flake = {
    # system independent outputs like nixosModules, nixosConfigurations, etc.

    # nixosConfigurations.example-host = ...
  };
}
