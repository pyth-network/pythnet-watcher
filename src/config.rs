use std::path::PathBuf;

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
    #[arg(long = "wormhole-pid", env = "WORMHOLE_PID", default_value = "H3fxXJ86ADW2PNuDDmZJg6mzTtPxkYCpNuQUTgmJ7AjU")]
    pub wormhole_pid: String,
    /// The address of the accumulator contract.
    #[arg(long = "accumulator-address", env = "ACCUMULATOR_ADDRESS", default_value = "G9LV2mp9ua1znRAfYwZz5cPiJMAbo1T6mbjdQsDZuMJg")]
    pub accumulator_address: String,
}
