use signal_cli_client::run_cli;

#[tokio::main]
async fn main() {
    let _ = run_cli().await;
}
