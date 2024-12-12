{
  self,
  lib,
  inputs,
  ...
}:
let
  evaluatedSystem = inputs.nixpkgs.lib.nixosSystem {
    modules = [ ./configuration.nix ];
    system = "x86_64-linux";
    specialArgs = self.specialArgs;
  };
in
{
  flake.nixosConfigurations."${evaluatedSystem.config.passthru.hostName}" = evaluatedSystem;
}
