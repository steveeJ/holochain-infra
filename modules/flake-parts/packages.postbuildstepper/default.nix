{
  # System independent arguments.
  self,
  inputs,
  ...
}:
{
  perSystem =
    {
      # Arguments specific to the `perSystem` context.
      pkgs,
      self',
      system ? pkgs.system,
      lib,
      ...
    }:

    {
      # system specific outputs like, apps, checks, packages

      packages =
        let
          cranePkgs = inputs.craneNixpkgs.legacyPackages.${system};
          craneLib = inputs.crane.mkLib cranePkgs;

          postbuildstepperArgs =
            let
              pname = "postbuildstepper";
            in
            {
              inherit pname;

              src = self.inputs.nix-filter {
                root = self;
                # If no include is passed, it will include all the paths.
                include = [
                  # Include the "src" path relative to the root.
                  "applications/postbuildstepper"
                  # Include this specific path. The path must be under the root.
                  "Cargo.toml"
                  "Cargo.lock"
                  # Include all files with the .js extension
                ];
              };

              version = "alpha";

              cargoExtraArgs = "--bins";

              nativeBuildInputs = [ cranePkgs.pkg-config ];

              doCheck = true;
            };
          postbuildstepperDeps = lib.makeOverridable craneLib.buildDepsOnly postbuildstepperArgs;
        in
        {
          postbuildstepper-testpkg = pkgs.runCommand "postbuildstepper-testpkg" { } ''
            mkdir -p $out/bin
            echo "echo hello postbuildstepper" > $out/bin/postbuildstepper-testpkg
          '';

          postbuildstepper = lib.makeOverridable craneLib.buildPackage (
            postbuildstepperArgs // { cargoArtifacts = postbuildstepperDeps; }
          );

        };

      checks =
        let
          s3 = {
            bucket = "cache.holo.host";
            endpoint = "s3.wasabisys.com";
            adminKey = "s3key";
            adminSecret = "s3secret";
            profile = "cache-holo-host-s3-wasabi";

            userKey = "s3user";
            userSecret = "s3usersecret";

            endpointCert = self.lib.makeCert {
              inherit pkgs;
              caName = "Example good CA";
              domain = "${s3.endpoint}";
            };

            bucketCert = self.lib.makeCert {
              inherit pkgs;
              caName = "Example good CA";
              domain = "${s3.bucket}";
            };
          };

          awsSharedCredentialsFile = pkgs.writeText "aws-shared-credentials" ''
            [${s3.profile}]
            aws_access_key_id = ${s3.userKey}
            aws_secret_access_key = ${s3.userSecret}'';

          cacheSecretKey = "testing-2:CoS7sAPcH1M+LD+D/fg9sc1V3uKk88VMHZ/MvAJHsuMSasehxxlUKNa0LUedGgFfA1wlRYF74BNcAldRxX2g8A==";
          cachePublicKey = "testing-2:EmrHoccZVCjWtC1HnRoBXwNcJUWBe+ATXAJXUcV9oPA=";
        in
        lib.attrsets.optionalAttrs (pkgs.stdenv.isLinux && pkgs.stdenv.isx86_64) {
          postbuildstepper-test = pkgs.writeShellScriptBin "test" ''
            set -x

            export PROP_owners="['steveej']"
            export PROP_repository="https://github.com/Holo-Host/holo-nixpkgs"
            export PROP_project="Holo-Host/holo-nixpkgs" \
            export PROP_attr="aarch64-linux.${self'.packages.postbuildstepper-testpkg.name}"
            export SECRET_cacheHoloHost2secret="${cacheSecretKey}"
            export PROP_out_path="${self'.packages.postbuildstepper-testpkg}"
            # this needs to be `cat`ed because the program expects this to contain the content of the file.
            export SECRET_awsSharedCredentialsFile="$(cat ${awsSharedCredentialsFile})"

            exec ${pkgs.lib.getExe' self.packages.${system}.postbuildstepper "postbuildstepper"}
          '';

          tests-postbuildstepper-integration = inputs.nixpkgs.lib.nixos.runTest {
            name = "postbuildstepper";

            imports = [ ];
            hostPkgs = pkgs; # the Nixpkgs package set used outside the VMs
            # defaults.services.foo.package = self'.packages.postbuildstepper;

            # One or more machines:
            nodes = {
              machine =
                { config, pkgs, ... }:

                {
                  networking.hosts = {
                    "127.0.0.1" = [
                      s3.bucket
                      s3.endpoint
                    ];
                  };

                  security.pki.certificateFiles = [
                    "${s3.endpointCert}/ca.crt"
                    "${s3.bucketCert}/ca.crt"
                  ];

                  nix.settings.experimental-features = [
                    "nix-command"
                    "flakes"
                  ];

                  # add the testpkg to the closure at buildtime. otherwise `nix sign/copy` will try to build or fetch it
                  environment.systemPackages = [ self'.packages.postbuildstepper-testpkg ];

                  services.minio = {
                    enable = true;
                    browser = false;
                    listenAddress = "127.0.0.1:9000";
                    rootCredentialsFile = pkgs.writeText "creds" ''
                      MINIO_ROOT_USER=${s3.adminKey}
                      MINIO_ROOT_PASSWORD=${s3.adminSecret}
                    '';
                  };

                  services.caddy = {
                    enable = true;
                    logFormat = ''
                      # if need be set to DEBUG
                      level INFO
                    '';
                    globalConfig = ''
                      auto_https off
                    '';

                    virtualHosts.${s3.endpoint} = {
                      extraConfig = ''
                        tls ${s3.endpointCert}/server.crt ${s3.endpointCert}/server.key
                        reverse_proxy http://${config.services.minio.listenAddress}
                      '';
                    };
                    virtualHosts.${s3.bucket} = {
                      extraConfig = ''
                        tls ${s3.bucketCert}/server.crt ${s3.bucketCert}/server.key
                        rewrite * /${s3.bucket}{uri}
                        reverse_proxy http://${config.services.minio.listenAddress}
                      '';
                    };
                  };
                };
            };

            testScript = ''
              machine.start()

              machine.wait_for_unit("minio.service")
              # uncomment this command get a minio trace log
              # machine.execute(
              #   ${pkgs.writeShellScript "trace-minio" ''
                #     export PATH=${pkgs.minio-client}/bin:$PATH
                #     set -xe
                #     # background trace logging for minio
                #     mc admin trace --all localhost >&2 &
                #   ''},
              #   timeout = None
              # )


              machine.wait_for_unit("caddy.service")

              machine.succeed("${pkgs.writeShellScript "prepare-minio" ''
                export PATH=${pkgs.minio-client}/bin:$PATH

                set -xe

                mc alias set localhost "https://${s3.endpoint}" "${s3.adminKey}" "${s3.adminSecret}"
                mc mb localhost/${s3.bucket}

                # create a non-admin user with write permissions
                mc admin user add localhost ${s3.userKey} ${s3.userSecret}
                mc admin policy attach localhost readwrite --user ${s3.userKey}
                mc alias set user "https://${s3.endpoint}" "${s3.userKey}" "${s3.userSecret}"

                # allow anonymous access to the "cache"
                mc anonymous set --recursive download localhost/${s3.bucket}

                # this file is GET'ed by `nix copy`
                echo "StoreDir: /nix/store" > nix-cache-info
                mc cp nix-cache-info user/${s3.bucket}/nix-cache-info
                # mc cp nix-cache-info localhost/${s3.bucket}/nix-cache-info

                for remote in \
                    https://${s3.endpoint}/${s3.bucket}/nix-cache-info \
                    https://${s3.bucket}/nix-cache-info \
                    ; do
                  diff --report-identical-files <(curl ''${remote}) nix-cache-info
                done


              ''}", timeout = 10)

              machine.succeed("${lib.getExe self'.checks.postbuildstepper-test}", timeout = 30)

              machine.succeed("nix copy --trusted-public-keys ${cachePublicKey} --from https://cache.holo.host --to ./store ${self'.packages.postbuildstepper-testpkg}", timeout = 30)
            '';
          };
        };
    };

  flake = {
    # system independent outputs like nixosModules, nixosConfigurations, etc.

    # nixosConfigurations.example-host = ...
  };
}
