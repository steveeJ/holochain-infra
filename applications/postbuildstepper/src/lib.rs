pub mod util {
    use std::{ffi::OsStr, path::Path, process::Stdio};

    use anyhow::{bail, Context};

    pub fn nix_cmd_helper<I, J, K, V, L>(args: I, envs: J) -> anyhow::Result<()>
    where
        I: IntoIterator<Item = K>,
        J: IntoIterator<Item = (V, L)>,
        K: AsRef<OsStr>,
        V: AsRef<OsStr>,
        L: AsRef<OsStr>,
    {
        let mut cmd = std::process::Command::new("nix");
        cmd.args(args)
            .envs(envs)
            // pass stdio through so it becomes visible in the log
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit());

        let context = format!("running {cmd:#?}");

        let mut spawned = cmd.spawn().context(context.clone())?;
        let finished = spawned.wait().context(context.clone())?;
        if !finished.success() {
            bail!("{context} failed.");
        }

        Ok(())
    }

    pub fn try_to_str(p: &Path) -> Result<&str, anyhow::Error> {
        let signing_key_file_path = p.to_str().ok_or_else(|| {
            anyhow::anyhow!(
                "could not convert {} (lossy) to string",
                p.to_string_lossy()
            )
        })?;

        Ok(signing_key_file_path)
    }

    pub fn is_re_match_lossy(re: &str, attr: &str, prefix: &str) -> anyhow::Result<bool> {
        let compiled_re = pcre2::bytes::Regex::new(re)?;
        let is_match = compiled_re.is_match(attr.as_bytes())?;

        log::debug!("[{attr}/{prefix}]: '{re}' matched '{attr}': {is_match}");

        Ok(is_match)
    }
}

pub mod business {
    use anyhow::{anyhow, bail, Context, Result};
    use core::time;
    use log::{debug, info, trace, warn};
    use reqwest::header::USER_AGENT;
    use serde_json::json;
    use std::{
        char::ToLowercase,
        collections::{HashMap, HashSet},
        ffi::OsString,
        io::Write,
        rc::Rc,
    };
    use tempfile::NamedTempFile;

    use super::util::is_re_match_lossy;

    // TODO(backlog): create a config map for these
    const CHANNELS_DIRECTORY_ENV_KEY: &str = "PBS_CHANNELS_DIRECTORY";
    const CHANNELS_JOBSETS_ENV_KEY: &str = "PBS_JOBSETS_DIRECTORY";
    const HOLO_NIXPKGS_RELEASE_ATTR: &str = "x86_64-linux.holo-nixpkgs-release";
    /// Contains a comma separated list of source branches from which named channels will be created
    const SOURCE_BRANCH_CHANNELS_ENV_KEY: &str = "SOURCE_BRANCH_CHANNELS";

    #[derive(Debug)]
    pub struct BuildInfo(HashMap<String, String>);

    // FIXME: is hardocing these in a type and functions sustainable, or is a config map appropriate?
    impl BuildInfo {
        // example var: 'PROP_project=holochain/holochain-infra
        pub fn from_env() -> Self {
            let env_vars = HashMap::<String, String>::from_iter(std::env::vars());

            let new_self = Self(env_vars);
            trace!("env vars: {new_self:#?}");

            new_self
        }

        // allows looking up variables in the internal map
        pub fn get(&self, var: &str) -> Result<&String> {
            self.0
                .get(var)
                .ok_or_else(|| anyhow::anyhow!("looking up {var} in {self:#?}"))
        }

        pub fn try_owners(&self) -> Result<HashSet<String>> {
            let value = self.get("PROP_owners")?;
            let vec: Vec<String> = serde_json::from_str(&value.replace("\'", "\""))
                .context(format!("parsing {value:?} as JSON"))?;

            Ok(HashSet::from_iter(vec))
        }
        pub fn try_org_repo(&self) -> Result<(&str, &str)> {
            let value = self.get("PROP_project")?;

            if let Some(split) = value.split_once("/") {
                Ok(split)
            } else {
                bail!("couldn't parse project {value}");
            }
        }

        pub fn try_attr(&self) -> Result<&String> {
            self.get("PROP_attr")
        }

        pub fn try_out_path(&self) -> Result<String> {
            let var = "PROP_out_path";
            let from_env = self.get(var)?;
            let canonical = std::fs::canonicalize(from_env)
                .context(format!("canonicalizing value from {var}: '{from_env}'"))?;
            let displayed = super::util::try_to_str(&canonical)?;

            Ok(displayed.to_string())
        }

        /// Example: PROP_repository=https://github.com/holochain/holochain-infra
        pub fn try_repository(&self) -> Result<&String> {
            self.get("PROP_repository")
        }

        /// Example: PROP_event=pull_request
        pub async fn try_event(&self) -> Result<BuildInfoEvent> {
            let raw = self.get("PROP_event")?;

            match raw.as_str() {
                "pull_request" => {
                    let url = self.try_pullrequesturl()?;
                    let number = url
                        .rsplit_once("/")
                        .ok_or(anyhow!("couldn't find '/' in {url}"))?
                        .1
                        .to_string();
                    let (forge, source_branch) =
                        if let Ok(override_source_branch) = self.get("OVERRIDE_SOURCE_BRANCH") {
                            (Forge::Mock, override_source_branch.clone())
                        } else if url.starts_with("https://github.com") {
                            let forge = Forge::Github;
                            let source_branch =
                                self.pullrequest_get_source_branch_github(&number).await?;

                            (forge, source_branch)
                        } else {
                            bail!("unknown forge with url: {url}");
                        };

                    Ok(BuildInfoEvent::PullRequest {
                        number,
                        source_branch,
                        forge,
                    })
                }
                "push" => {
                    let repository = self.try_repository()?;
                    let forge = if repository.starts_with("https://github.com") {
                        Forge::Github
                    } else {
                        bail!("unknown forge with repository: {repository}");
                    };
                    let destination_branch = self.try_branch()?.to_string();

                    Ok(BuildInfoEvent::Push {
                        destination_branch,
                        forge,
                    })
                }

                _ => bail!("unsupported event: {raw}"),
            }
        }

        fn try_revision(&self) -> Result<&String> {
            self.get("PROP_revision")
        }

        /// queries the github API to find the source branch of this pullrequest
        /// relies on credentials from the environment in ``
        pub async fn pullrequest_get_source_branch_github(&self, number: &str) -> Result<String> {
            let maybe_github_user_and_pat_ini =
                self.try_github_user_pat()?.lines().find_map(|line| {
                    let (key, value) = line
                        .split_once("=")
                        .map(|(k, v)| ((k.trim().trim_matches('"')), (v.trim().trim_matches('"'))))
                        .unwrap_or_default();

                    let value_reveal_start = std::cmp::max(3, value.len() / 8);
                    let dedacted_value = &value
                        .get(value.len() - value_reveal_start..value.len())
                        .unwrap_or("<unknown>");
                    if key == "NIX_GITHUB_PRIVATE_PAT" {
                        debug!("token found at '{key}=..{dedacted_value}'");
                        Some(value)
                    } else {
                        debug!("token not found at '{key}=..{dedacted_value}'");
                        None
                    }
                });
            let bearer = if let Some(github_user_and_pat_ini) = maybe_github_user_and_pat_ini {
                github_user_and_pat_ini
            } else {
                bail!("no github secret, can't determine pull-request source branch");
            };
            let url = {
                let (org, repo) = self.try_org_repo()?;

                format!("https://api.github.com/repos/{org}/{repo}/pulls/{number}")
            };
            let req = reqwest::Client::new()
                .get(&url)
                .header("Accept", "application/vnd.github+json")
                .header("X-GitHub-Api-Version", "2022-11-28")
                .header(
                    USER_AGENT,
                    concat!(env!("CARGO_PKG_NAME"), "/", env!("CARGO_PKG_VERSION")),
                )
                .bearer_auth(bearer)
                .timeout(time::Duration::from_secs(10));

            debug!("{url} request: {req:#?}");

            let response = req
                .send()
                .await
                .context(format!("querying {url}"))?
                .error_for_status()?
                .text()
                .await?;

            let level0value: serde_json::Value = serde_json::from_str(&response)?;
            Ok(
                if let Some(source_branch) = level0value
                    .as_object()
                    .and_then(|level0obj| level0obj.get("head"))
                    .and_then(|level1value| level1value.as_object())
                    .and_then(|level1obj| level1obj.get("ref"))
                    .and_then(|head_ref_value| head_ref_value.as_str())
                    // the JSON value is in quotes, remove them
                    .map(|head_ref| head_ref.trim_matches('"').to_string())
                {
                    source_branch
                } else {
                    bail!("couldn't find something at path '.head.ref' in {response}");
                },
            )
        }

        fn try_pullrequesturl(&self) -> Result<&String> {
            self.get("PROP_pullrequesturl")
        }

        fn try_github_user_pat(&self) -> Result<&String> {
            self.get("SECRET_githubUserAndPat")
        }

        fn try_branch(&self) -> Result<&String> {
            self.get("PROP_branch")
        }
    }

    /// Represents information about the event, e.g. a pull request.
    #[derive(Debug)]
    pub enum BuildInfoEvent {
        PullRequest {
            number: String,
            source_branch: String,
            forge: Forge,
        },
        Push {
            destination_branch: String,
            forge: Forge,
        },
    }

    #[derive(Debug)]
    pub enum Forge {
        Github,
        Mock,
    }

    /// Verifies that the build current owners are trusted. Checks are case-insensitive.
    // FIXME: make trusted owners configurable
    pub fn check_owners(owners: HashSet<String>, org: &str, _repo: &str) -> anyhow::Result<()> {
        const TRUSTED_OWNERS: &[&str] = &[
            // bots
            "github-actions",
        ];

        const TRUSTED_OWNERS_PER_ORG: &[(&str, &[&str])] = &[
            (
                "holochain",
                &[
                    // admins
                    "steveej",
                    "Stefan Junker <mail@stefanjunker.de>",
                    "evangineer",
                    // devs
                    "ThetaSinner",
                    "cdunster",
                    "zippy",
                ],
            ),
            (
                "holo-host",
                &[
                    "steveej",
                    "Stefan Junker <mail@stefanjunker.de>",
                    "evangineer",
                    "JettTech",
                    "mattgeddes",
                    "zeeshan595",
                    "mattgeddes",
                    "alastairong1",
                ],
            ),
        ];

        let org = org.to_lowercase();

        let mut trusted_owners =
            HashSet::<String>::from_iter(TRUSTED_OWNERS.iter().map(|s| s.to_lowercase()));
        trusted_owners.extend(
            HashMap::<String, HashSet<String>>::from_iter(TRUSTED_OWNERS_PER_ORG.iter().map(
                |(k, v)| {
                    (
                        k.to_lowercase(),
                        HashSet::from_iter(v.iter().map(|s| s.to_lowercase())),
                    )
                },
            ))
            .get(&org)
            .cloned()
            .unwrap_or_default(),
        );
        let owner_is_trusted = owners
            .iter()
            .map(|s| s.to_lowercase())
            .collect::<HashSet<_>>()
            .is_subset(&trusted_owners);
        if !owner_is_trusted {
            bail!("{owners:?} are *NOT* among trusted users for {org}: {trusted_owners:?}");
        }
        info!("owners {owners:?} are trusted! proceeding.");

        Ok(())
    }

    /// Contains information to sign and upload the build results
    pub struct SigningAndCopyInfo {
        pub signing_key_file: NamedTempFile,
        pub copy_envs: HashMap<OsString, NamedTempFile>,
        pub copy_destination: String,
        pub extra_nix_arg: Option<&'static str>,
    }

    /// Evaluates the project org and accordingly returns a signing key.
    pub fn may_get_signing_key_and_copy_info(
        build_info: &BuildInfo,
    ) -> anyhow::Result<Option<SigningAndCopyInfo>> {
        let (org, _) = build_info.try_org_repo()?;

        let wrap_secret_in_tempfile = |s: &str| -> anyhow::Result<_> {
            let mut tempfile = NamedTempFile::new()?;
            tempfile.write_all(s.as_bytes())?;
            Ok(tempfile)
        };

        if org == "Holo-Host" {
            // FIXME: create a constant or config value for this
            let signing_secret = build_info.get("SECRET_cacheHoloHost2secret")?;
            let copy_envs = HashMap::from_iter([(
                // FIXME: create a constant or config value for this
                OsString::from("AWS_SHARED_CREDENTIALS_FILE"),
                wrap_secret_in_tempfile(build_info.get("SECRET_awsSharedCredentialsFile")?)?,
            )]);

            let copy_destination = {
                // FIXME: create a config map for all the below

                let s3_bucket = "cache.holo.host";
                let s3_endpoint = "s3.wasabisys.com";
                let s3_profile = "cache-holo-host-s3-wasabi";

                format!("s3://{s3_bucket}?")
                    + &[
                        vec![
                            format!("endpoint={s3_endpoint}"),
                            format!("profile={s3_profile}"),
                        ],
                        [
                            "log-compression=br",
                            "ls-compression=br",
                            "parallel-compression=1",
                            "write-nar-listing=1",
                        ]
                        .into_iter()
                        .map(ToString::to_string)
                        .collect(),
                    ]
                    .concat()
                    .join("&")
            };

            Ok(Some(SigningAndCopyInfo {
                signing_key_file: wrap_secret_in_tempfile(signing_secret)?,
                copy_envs,
                copy_destination,
                extra_nix_arg: None,
            }))
        } else if org == "holochain" {
            info!("{org} doesn't have any credentials for signing and copying builds.");
            Ok(None)
        } else {
            bail!("unknown org: {org}")
        }
    }

    pub fn evaluate_filters(build_info: &BuildInfo) -> Result<bool, anyhow::Error> {
        const HOLOCHAIN_INFRA_REPO: &str = "https://github.com/holochain/holochain-infra";
        const HOLO_NIXPKGS_REPO: &str = "https://github.com/Holo-Host/holo-nixpkgs";

        #[derive(Default)]
        struct Filters {
            include_filters_re: Rc<[Rc<str>]>,
            exclude_filters_re: Rc<[Rc<str>]>,
        }

        let filters_by_repo = HashMap::<_, _>::from_iter([
            (
                HOLOCHAIN_INFRA_REPO,
                Filters {
                    include_filters_re: [HOLO_NIXPKGS_RELEASE_ATTR].map(Into::into).into(),
                    exclude_filters_re: [].into(),
                },
            ),
            (
                HOLO_NIXPKGS_REPO,
                Filters {
                    include_filters_re: [".*"].map(Into::into).into(),
                    exclude_filters_re: [".*tests.*".into()].into(),
                },
            ),
        ]);
        let repo = build_info.try_repository()?;
        let attr = build_info.try_attr()?;

        let conclusion = if let Some(filters) = filters_by_repo.get(repo.as_str()) {
            let include = filters
                .include_filters_re
                .iter()
                .try_fold(false, |prev, re| {
                    anyhow::Ok(prev || is_re_match_lossy(re, attr, "include")?)
                })?;

            let exclude = filters
                .exclude_filters_re
                .iter()
                .try_fold(false, |prev, re| {
                    anyhow::Ok(prev || is_re_match_lossy(re, attr, "include")?)
                })?;

            let conclusion = include && !exclude;

            debug!("[{attr}]: include: {include}, exclude: {exclude}, conclusion: {conclusion}");
            conclusion
        } else {
            warn!("no filters found for {repo}");
            false
        };

        Ok(conclusion)
    }

    pub async fn process_holo_nixpkgs_release(
        build_info: BuildInfo,
    ) -> Result<Option<Vec<String>>, anyhow::Error> {
        if build_info.try_org_repo()? == ("Holo-Host", "holo-nixpkgs")
            && build_info.try_attr()? == HOLO_NIXPKGS_RELEASE_ATTR
        {
            let channel_attr_out_path = build_info.try_out_path()?;
            let tarball_path =
                std::path::Path::new(&channel_attr_out_path).join("tarballs/nixexprs.tar.xz");
            if !tarball_path.exists() {
                bail!("{tarball_path:#?} doesn't exist");
            }

            let pbs_channels_directory: &str = build_info.get(CHANNELS_DIRECTORY_ENV_KEY)?;
            let pbs_jobsets_directory: &str = build_info.get(CHANNELS_JOBSETS_ENV_KEY)?;

            let maybe_channel_names = match build_info.try_event().await? {
                BuildInfoEvent::PullRequest {
                    number,
                    source_branch,
                    ..
                } => {
                    let source_branch_channels = HashSet::<&str>::from_iter(
                        build_info.get(SOURCE_BRANCH_CHANNELS_ENV_KEY)?.split(","),
                    );
                    debug!("will create channels for these source branches: {source_branch_channels:#?}");
                    let mut channel_names = vec![number];
                    if source_branch_channels.contains(source_branch.as_str()) {
                        channel_names.push(source_branch);
                    };
                    Some(channel_names)
                }
                BuildInfoEvent::Push {
                    destination_branch, ..
                } => Some(vec![destination_branch]),
            };

            if let Some(channel_names) = &maybe_channel_names {
                let revision = build_info.try_revision()?;

                create_channel_artifacts(
                    revision,
                    channel_names.as_slice(),
                    pbs_channels_directory,
                    tarball_path,
                    pbs_jobsets_directory,
                )?;
            }

            Ok(maybe_channel_names)
        } else {
            Ok(None)
        }
    }

    fn create_channel_artifacts(
        revision: &String,
        channel_names: &[String],
        pbs_channels_directory: &str,
        tarball_path: std::path::PathBuf,
        pbs_jobsets_directory: &str,
    ) -> Result<(), anyhow::Error> {
        info!("creating channel artifacts at revision '{revision}' with names '{channel_names:?}'");

        for channel_name in channel_names {
            {
                // symlink the tarball to <base-path>/<channel-name>/holo-nixpkgs/nixexprs.tar.xz
                let tarball_link_output_dir = std::path::Path::new(pbs_channels_directory)
                    .join(channel_name)
                    // TODO(backlog): read this from environment
                    .join("holo-nixpkgs");
                // TODO(backlog): create config map for this
                let tarball_link_output_path = tarball_link_output_dir.join("nixexprs.tar.xz");
                let tarball_link_output_path_tmp =
                    tarball_link_output_dir.join("nixexprs.tar.xz.tmp");

                std::fs::create_dir_all(&tarball_link_output_dir).context(format!(
                    "creating to contain symlink {tarball_link_output_dir:#?}"
                ))?;

                if std::fs::exists(&tarball_link_output_path_tmp).context(format!(
                    "checking the existence of {tarball_link_output_path_tmp:#?}"
                ))? {
                    std::fs::remove_file(&tarball_link_output_path_tmp)
                        .context(format!("removing {tarball_link_output_path_tmp:#?}"))?;
                }

                std::os::unix::fs::symlink(&tarball_path, &tarball_link_output_path_tmp).context(
                    format!(
                        "create symlink to {tarball_path:#?} at {tarball_link_output_path_tmp:#?}"
                    ),
                )?;
                std::fs::rename(&tarball_link_output_path_tmp, &tarball_link_output_path).context(
                    format!(
                    "renaming {tarball_link_output_path_tmp:#?} to {tarball_link_output_path:#?}"
                ),
                )?;

                info!(
                    "created tarball symlink to {tarball_path:#?} at {tarball_link_output_path:#?}"
                );
            }

            let latest_eval_json = json!(
                { "jobsetevalinputs": { "holo-nixpkgs": { "revision": revision, } } }
            )
            .to_string();

            {
                /*
                reproduce the latest-eval necessary fields. informed by this curl command:

                $ curl -L -H Content-Type:application/json "https://hydra.holo.host/jobset/holo-nixpkgs/2410/latest-eval" | jq -r '.jobsetevalinputs | .holo-nixpkgs | .revision'
                71ab117ef134c645b61f2493ca5dfe06970158bc
                */

                let jobset_output_dir =
                    std::path::Path::new(pbs_jobsets_directory).join(channel_name);

                let jobset_output_path = jobset_output_dir.join("latest-eval");
                let jobset_output_path_tmp = jobset_output_dir.join("latest-eval.tmp");

                std::fs::create_dir_all(&jobset_output_dir).context(format!(
                    "creating to contain symlink {jobset_output_dir:#?}"
                ))?;

                if std::fs::exists(&jobset_output_path_tmp).context(format!(
                    "checking the existence of {jobset_output_path_tmp:#?}"
                ))? {
                    std::fs::remove_file(&jobset_output_path_tmp)
                        .context(format!("removing {jobset_output_path_tmp:#?}"))?;
                }

                std::fs::write(&jobset_output_path_tmp, &latest_eval_json).context(format!(
                    "write {latest_eval_json} to {jobset_output_path_tmp:#?}"
                ))?;

                std::fs::rename(&jobset_output_path_tmp, &jobset_output_path).context(format!(
                    "renaming {jobset_output_path_tmp:#?} to {jobset_output_path:#?}"
                ))?;

                debug!("wrote '{latest_eval_json}' to {jobset_output_path:#?}");
            }
        }

        Ok(())
    }

    #[cfg(test)]
    mod tests {
        use test_log::test;

        use std::{collections::HashMap, fs::File, io::Write, path::Path};

        use tempfile::tempdir;

        use crate::business::{BuildInfo, CHANNELS_DIRECTORY_ENV_KEY, CHANNELS_JOBSETS_ENV_KEY};

        use super::process_holo_nixpkgs_release;

        fn recurse_and_print<T: IntoIterator<Item = Result<std::fs::DirEntry, std::io::Error>>>(
            entries: T,
            seen: &mut std::collections::HashSet<std::path::PathBuf>,
        ) {
            for entry in entries {
                let entry = entry.unwrap();
                let entry_path = entry.path();
                let file_type = entry.file_type().unwrap();
                log::debug!("entry: {entry:#?}");
                if file_type.is_dir() && !seen.insert(entry_path.clone()) {
                    recurse_and_print(std::fs::read_dir(entry_path).unwrap(), seen);
                }
            }
        }

        #[test(tokio::test)]
        async fn test_process_holo_nixpkgs_release() {
            let mk_buildinfo = |temppath: &Path, source_branch_channels| {
                BuildInfo(HashMap::from_iter(
                    [
                        // TODO: extract some of these into consts that are shared with the code
                        ("PROP_project", "Holo-Host/holo-nixpkgs"),
                        ("PROP_attr", "x86_64-linux.holo-nixpkgs-release"),
                        ("PROP_out_path", temppath.to_str().unwrap()),
                        ("PROP_event", "pull_request"),
                        ("PROP_pullrequesturl", "/1"),
                        ("OVERRIDE_SOURCE_BRANCH", "one"),
                        ("SOURCE_BRANCH_CHANNELS", source_branch_channels),
                        ("PROP_revision", "1231"),
                        (
                            CHANNELS_DIRECTORY_ENV_KEY,
                            temppath.join("channels").to_str().unwrap(),
                        ),
                        (
                            CHANNELS_JOBSETS_ENV_KEY,
                            temppath.join("jobsets").to_str().unwrap(),
                        ),
                    ]
                    .map(|(k, v)| (k.to_string(), v.to_string())),
                ))
            };

            for (source_branch_channels, expected) in [
                ("", None),
                ("one", Some(vec!["1".to_string(), "one".to_string()])),
            ] {
                let tempdir = tempdir().unwrap();

                let out_path = tempdir.path().join("tarballs/nixexprs.tar.xz");
                std::fs::create_dir_all(out_path.parent().unwrap()).unwrap();
                let mut out_path_file = File::create_new(&out_path).unwrap();
                out_path_file
                    .write_all("not a real archive".as_bytes())
                    .unwrap();

                let maybe_channel_names = process_holo_nixpkgs_release(mk_buildinfo(
                    tempdir.path(),
                    source_branch_channels,
                ))
                .await
                .unwrap();

                assert_eq!(maybe_channel_names, expected);

                // for debugging purposes
                recurse_and_print(
                    std::fs::read_dir(tempdir.path()).unwrap(),
                    &mut Default::default(),
                );
            }
        }
    }
}
