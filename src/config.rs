use clap::Parser;

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
    pub wormhole_pid:    String,
    #[arg(long = "server-url", env = "SERVER_URL")]
    pub server_url:      String,
}
