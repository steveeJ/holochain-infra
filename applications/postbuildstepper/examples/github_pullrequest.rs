/// Expects to be called like this:
/// env \
///   SECRET_githubUserAndPat=NIX_GITHUB_PRIVATE_PAT=github_pat_*** \
///   PROP_project=Holo-Host/holo-nixpkgs \
///   RUST_LOG=trace \
///   cargo run --example github_pullrequest 2410
use postbuildstepper::business::BuildInfo;

#[tokio::main]
async fn main() {
    let build_info = BuildInfo::from_env();

    env_logger::builder()
        .filter_level(log::LevelFilter::Debug)
        .init();

    let arg1 = std::env::args().nth(1).unwrap();

    build_info
        .pullrequest_get_source_branch_github(&arg1)
        .await
        .unwrap();
}
