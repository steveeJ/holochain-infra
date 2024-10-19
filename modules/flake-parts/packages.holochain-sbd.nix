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

          sbdArgs = {
            pname = "sbd";
            src = inputs.sbd;
            version = inputs.sbd.rev;
            cargoExtraArgs = "--examples --bins";
            nativeBuildInputs = [ pkgs.pkg-config ];
            buildInputs = [ pkgs.openssl ];

            doCheck = false;
          };
          sbdDeps = lib.makeOverridable craneLib.buildDepsOnly sbdArgs;
        in
        {
          sbd = lib.makeOverridable craneLib.buildPackage (sbdArgs // { cargoArtifacts = sbdDeps; });

          sbd-serverd = self'.packages.sbd.override {
            name = "sbd-serverd";
            cargoExtraArgs = "--bin sbd-serverd";
            meta.mainProgram = "sbd-serverd";
          };
        };
    };
  flake = {
    # system independent outputs like nixosModules, nixosConfigurations, etc.

    # nixosConfigurations.example-host = ...
  };
}
