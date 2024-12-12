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

    let
      cranePkgs = inputs.craneNixpkgs.legacyPackages.${system};
      craneLib = inputs.crane.mkLib cranePkgs;

    in

    {

      # system specific outputs like, apps, checks, packages
      packages =
        let

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

              buildInputs = [ cranePkgs.openssl ];

              doCheck = true;
            };
          postbuildstepperDeps = craneLib.buildDepsOnly postbuildstepperArgs;

          mkPostbuildstepper =
            { craneLib, ... }@args: craneLib.buildPackage (builtins.removeAttrs args [ "craneLib" ]);
        in
        {
          postbuildstepper = lib.makeOverridable mkPostbuildstepper (
            postbuildstepperArgs
            // {
              inherit craneLib;
              cargoArtifacts = postbuildstepperDeps;
            }
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

          github = {
            fixture = lib.importJSON "${self}/applications/postbuildstepper/fixtures/pull2410.json";
            project = github.fixture.head.repo.full_name;
            repository = github.fixture.head.repo.html_url;
            testPullReqestNumber = builtins.toString github.fixture.number;
            testPullReqestHeadRef = github.fixture.head.ref;
            testBranch = "develop";
            path = "/repos/${github.project}/pulls/${github.testPullReqestNumber}";
            endpoint = "api.github.com";
            uri = "https://${github.endpoint}${github.path}";

            endpointCert = self.lib.makeCert {
              inherit pkgs;
              caName = "Example good CA";
              domain = "${github.endpoint}";
            };

            testPat = "github_testpat";
          };

          pbsChannelDirectory = "/tmp/hydra-compat/channels";
          pbsJobsetsDirectory = "/tmp/hydra-compat/jobsets";
          tarballTestString = "${github.testPullReqestNumber} ${github.testPullReqestNumber}";
          testRevision = "cfcc07f250cff8261d98fb652e1bab8b1fdc3509";
          pkgTarballPath = "tarballs/nixexprs.tar.xz";
          serveTarballPathNumber = "${pbsChannelDirectory}/${github.testPullReqestNumber}/holo-nixpkgs/nixexprs.tar.xz";
          serveTarballPathHeadRef = "${pbsChannelDirectory}/${github.testPullReqestHeadRef}/holo-nixpkgs/nixexprs.tar.xz";
          serveTarballPathBranch = "${pbsChannelDirectory}/${github.testBranch}/holo-nixpkgs/nixexprs.tar.xz";
          serveJobsetsPathNumber = "${pbsJobsetsDirectory}/${github.testPullReqestNumber}/latest-eval";
          serveJobsetsPathHeadRef = "${pbsJobsetsDirectory}/${github.testPullReqestHeadRef}/latest-eval";
          serveJobsetsPathBranch = "${pbsJobsetsDirectory}/${github.testBranch}/latest-eval";

          postbuildstepperTestpkg = pkgs.runCommand "postbuildstepper-testpkg" { } ''
            mkdir -p $out/bin
            echo "echo hello postbuildstepper" > $out/bin/postbuildstepper-testpkg

            mkdir -p $out/$(dirname ${pkgTarballPath})
            echo "${tarballTestString}" > $out/${pkgTarballPath}
          '';
          mkPostbuildstepperTest =
            { additionalExports }:
            pkgs.writeShellScript "test" ''
              set -x

              export PROP_owners="['steveej']"
              export PROP_repository="https://github.com/Holo-Host/holo-nixpkgs"
              export PROP_project="Holo-Host/holo-nixpkgs" \
              export PROP_attr="x86_64-linux.holo-nixpkgs-release"
              export SECRET_cacheHoloHost2secret="${cacheSecretKey}"
              export PROP_out_path="${postbuildstepperTestpkg}"
              # this needs to be `cat`ed because the program expects this to contain the content of the file.
              export SECRET_awsSharedCredentialsFile="$(cat ${awsSharedCredentialsFile})"

              export PBS_CHANNELS_DIRECTORY="${pbsChannelDirectory}"
              mkdir -p $PBS_CHANNELS_DIRECTORY
              export PBS_JOBSETS_DIRECTORY="${pbsJobsetsDirectory}"
              mkdir -p $PBS_JOBSETS_DIRECTORY

              export PROP_revision=${testRevision}

              export SECRET_githubUserAndPat="notoken=here
              NIX_GITHUB_PRIVATE_PAT=${github.testPat}"

              ${additionalExports}

              export RUST_BACKTRACE=full
              export RUST_LOG=trace
              exec ${pkgs.lib.getExe' self.packages.${system}.postbuildstepper "postbuildstepper"}
            '';

        in
        lib.attrsets.optionalAttrs (pkgs.stdenv.isLinux && pkgs.stdenv.isx86_64) {
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
                      github.endpoint
                    ];
                  };

                  security.pki.certificateFiles = [
                    "${s3.endpointCert}/ca.crt"
                    "${s3.bucketCert}/ca.crt"
                    "${github.endpointCert}/ca.crt"
                  ];

                  nix.settings.experimental-features = [
                    "nix-command"
                    "flakes"
                  ];
                  nix.settings.substituters = lib.mkForce [ "https://${s3.bucket}" ];
                  nix.settings.trusted-public-keys = [ cachePublicKey ];

                  # add the testpkg to the closure at buildtime. otherwise `nix sign/copy` will try to build or fetch it
                  environment.systemPackages = [
                    postbuildstepperTestpkg
                    pkgs.jq
                  ];

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
                      auto_https disable_certs
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
                    # mock the github API for the pullrequest query
                    virtualHosts."${github.endpoint}" = {
                      extraConfig =
                        let
                          root = pkgs.runCommand "fixture" { } ''
                            set -x
                            mkdir -p "$out/.$(dirname ${github.path})"
                            cp "${self}/applications/postbuildstepper/fixtures/pull2410.json" "$out/.${github.path}"
                          '';
                        in
                        ''
                          tls ${github.endpointCert}/server.crt ${github.endpointCert}/server.key

                          @authorized header "authorization" "Bearer ${github.testPat}"
                          @unauthorized expression `!header({'authorization':'Bearer ${github.testPat}'}) || !header({'user-agent':'*'})`

                          error @unauthorized "Unauthorized" 403

                          root @authorized ${root}
                          file_server @authorized
                        '';
                    };
                  };
                };
            };

            testScript = ''
              machine.start()

              machine.wait_for_unit("minio.service")
              machine.wait_for_unit("caddy.service")

              # NOTE(steveej)
              # minio startup seems to go beyond it's service being active.
              # hence, ensure that minio is actively the combination of caddy+minio are actively servicing requests.
              machine.wait_until_succeeds("${pkgs.writeShellScript "wait-for-minio" ''
                ${pkgs.minio-client}/bin/mc alias set localhost "https://${s3.endpoint}" "${s3.adminKey}" "${s3.adminSecret}"
              ''}",
                timeout = 10
              )

              # uncomment this command get a minio trace log
              # machine.execute("${pkgs.writeShellScript "trace-minio" ''
                #     export PATH=${pkgs.minio-client}/bin:$PATH
                #     set -xe
                #     # background trace logging for minio
                #     mc admin trace --all localhost >&2 &
                #   ''}",
              #   timeout = None
              # )

              machine.succeed("${pkgs.writeShellScript "prepare-minio" ''
                export PATH=${pkgs.minio-client}/bin:$PATH

                set -xe

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

                for remote in \
                    https://${s3.endpoint}/${s3.bucket}/nix-cache-info \
                    https://${s3.bucket}/nix-cache-info \
                    ; do
                  diff --report-identical-files <(curl ''${remote}) nix-cache-info
                done
              ''}", timeout = 10)

              cacheCheckCmd = "nix copy --refresh --verbose --from https://${s3.bucket} --to ./store ${postbuildstepperTestpkg}"

              ### test pull_request event
              tarballCheckCmdNumber = "grep '${tarballTestString}' ${serveTarballPathNumber}"
              tarballCheckCmdHeadref = "grep '${tarballTestString}' ${serveTarballPathHeadRef}"
              tarballCheckCmdBranch = "grep '${tarballTestString}' ${serveTarballPathBranch}"
              jobsetsCheckCmdNumber = """[[ ${testRevision} = $(jq -r '.jobsetevalinputs | ."holo-nixpkgs" | .revision' < ${serveJobsetsPathNumber}) ]]"""
              jobsetsCheckCmdHeadref = """[[ ${testRevision} = $(jq -r '.jobsetevalinputs | ."holo-nixpkgs" | .revision' < ${serveJobsetsPathHeadRef}) ]]"""

              with subtest("true negative pre-run pull_request"):
                machine.fail(cacheCheckCmd, timeout = 30)
                machine.fail(tarballCheckCmdNumber, timeout = 30)
                machine.fail(tarballCheckCmdHeadref, timeout = 30)
                machine.fail(jobsetsCheckCmdNumber, timeout = 30)
                machine.fail(jobsetsCheckCmdHeadref, timeout = 30)

              with subtest("simulate pull_request"):
                machine.succeed("${
                  mkPostbuildstepperTest {
                    additionalExports = ''
                      export PROP_event="pull_request"
                      export PROP_pullrequesturl="https://github.com/Holo-Host/holo-nixpkgs/pull/${github.testPullReqestNumber}"
                      export PROP_basename="develop"
                      export SOURCE_BRANCH_CHANNELS="${github.testPullReqestHeadRef}";
                    '';
                  }
                }", timeout = 30)

              with subtest("true positives post-run pull_request"):
                machine.succeed(cacheCheckCmd, timeout = 30)
                machine.succeed(tarballCheckCmdNumber, timeout = 30)
                machine.succeed(tarballCheckCmdHeadref, timeout = 30)
                machine.succeed(jobsetsCheckCmdNumber, timeout = 30)
                machine.succeed(jobsetsCheckCmdHeadref, timeout = 30)
              ###

              ### test push events
              jobsetsCheckCmdBranch = """[[ ${testRevision} = $(jq -r '.jobsetevalinputs | ."holo-nixpkgs" | .revision' < ${serveJobsetsPathBranch}) ]]"""

              with subtest("true negative pre-run push"):
                machine.fail(jobsetsCheckCmdBranch, timeout = 30)
              with subtest("simulate push"):
                machine.succeed("${
                  mkPostbuildstepperTest {
                    additionalExports = ''
                      export PROP_event="push"
                      export PROP_branch="${github.testBranch}"
                    '';
                  }
                }", timeout = 30)
              with subtest("true positives post-run push"):
                machine.succeed(jobsetsCheckCmdBranch, timeout = 30)
              ###

              # TODO(backlog): set up and test the served HTTPS endpoint for the tarball with nix-channel --add and nix-channel --update
              # TODO(backlog): set up and test the served HTTPS endpoint for the latest-eval with curl
            '';
          };
        };
    };

  flake = {
    # system independent outputs like nixosModules, nixosConfigurations, etc.

    # nixosConfigurations.example-host = ...
  };
}
