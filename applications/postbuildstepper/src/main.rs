/// This application is designed to be executed from within buildbot-nix in a postBuildStep.
/// It currently hardcodes assumptions that are specific to Holo/Holochain's build environment.
///
use anyhow::{Context, Ok};
use log::{info, warn};
use std::collections::HashMap;

use postbuildstepper::{
    business::{self, SigningAndCopyInfo},
    util,
};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::builder()
        .filter_level(log::LevelFilter::Debug)
        .init();

    let build_info = business::BuildInfo::from_env();

    let (org, repo) = build_info.try_org_repo()?;

    business::check_owners(build_info.try_owners()?, org, repo)?;

    let SigningAndCopyInfo {
        signing_key_file,
        extra_nix_arg,
        copy_envs,
        copy_destination,
    } = if let Some(info) = business::may_get_signing_key_and_copy_info(&build_info)? {
        info
    } else {
        warn!("got no signing/uploading credentials, exiting.");
        return Ok(());
    };

    if !business::evaluate_filters(&build_info)? {
        warn!("excluded by filters, exiting.");
        return Ok(());
    }

    let signing_key_file_path = util::try_to_str(signing_key_file.path())?;

    let store_path = build_info.try_out_path()?;

    // sign the store path
    util::nix_cmd_helper(
        [
            vec!["store", "sign", "--verbose", "--recursive", "--key-file"],
            if let Some(arg) = extra_nix_arg {
                vec![arg]
            } else {
                vec![]
            },
            vec![signing_key_file_path, &store_path],
        ]
        .concat(),
        HashMap::<&&str, &str>::new(),
    )?;
    info!("successfully signed store path {store_path}");

    // copy the store path
    util::nix_cmd_helper(
        ["copy", "--verbose", "--to", &copy_destination, &store_path],
        copy_envs.iter().map(|(k, v)| (k, v.path().as_os_str())),
    )
    .context(format!("pushing {store_path} to {copy_destination}"))?;
    info!("successfully pushed store path {store_path}");

    business::process_holo_nixpkgs_release(build_info).await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    // there's an integration test using nixos VM testing library. see `modules/flake-parts/packages.postbuildstepper/default.nix`
}
