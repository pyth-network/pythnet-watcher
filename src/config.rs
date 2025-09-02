use clap::Parser;

#[derive(clap::ValueEnum, Clone, Debug)]
pub enum Mode {
    Production,
    Development,
}

#[derive(Parser, Clone, Debug)]
pub struct RunOptions {
    /// The API key to use for auction server authentication.
    #[arg(long = "pythnet-url", env = "PYTHNET_URL")]
    pub pythnet_url: String,
    /// The Wormhole program ID.
    #[arg(
        long = "wormhole-pid",
        env = "WORMHOLE_PID",
        default_value = "H3fxXJ86ADW2PNuDDmZJg6mzTtPxkYCpNuQUTgmJ7AjU"
    )]
    pub wormhole_pid: String,
    #[arg(long = "server-url", env = "SERVER_URL", value_delimiter = ',')]
    pub server_urls: Vec<String>,
    #[arg(long = "mode", env = "MODE", default_value = "production")]
    pub mode: Mode,
    /// URI for the signer.
    /// https://github.com/wormhole-foundation/wormhole/blob/main/docs/guardian_signer.md
    #[arg(long = "signer-uri", env = "SIGNER_URI")]
    pub signer_uri: String,
    #[arg(
        long = "metrics-addr",
        env = "METRICS_ADDR",
        default_value = "127.0.0.1:9001"
    )]
    pub metrics_addr: String,
}

#[derive(Parser, Clone, Debug)]
pub struct GenerateKeyOptions {
    /// Output path for the generated secret key.
    #[arg(long = "output-file", env = "OUTPUT_FILE")]
    pub output_path: String,
}

#[derive(Parser, Debug)]
pub enum Command {
    /// Run the auction server service.
    Run(RunOptions),
    /// Run db migrations and exit.
    GenerateKey(GenerateKeyOptions),
}
