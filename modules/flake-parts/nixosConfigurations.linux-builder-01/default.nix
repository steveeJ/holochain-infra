{ self, inputs, ... }:
{
  flake.nixosConfigurations.linux-builder-01 = inputs.nixpkgs.lib.nixosSystem {
    modules = [ ./configuration.nix ];
    system = "x86_64-linux";
    specialArgs = self.specialArgs;
  };
}
