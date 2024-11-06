{ self, config, ... }:

{
  sops.secrets.holo-host-github-environment-secrets.sopsFile =
    self + "/secrets/buildbot-nix-0/github-secrets.yaml";
  systemd.services.nix-daemon.serviceConfig = {
    EnvironmentFile = [ config.sops.secrets.holo-host-github-environment-secrets.path ];
  };
}
