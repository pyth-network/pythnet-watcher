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
    /// Path to the file containing the secret key.
    #[arg(long = "secret-key", env = "SECRET_KEY")]
    pub secret_key_path: String,
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
