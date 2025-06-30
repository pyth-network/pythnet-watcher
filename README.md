# Pythnet Watcher

This project is a Rust-based utility for listening to messages on **Pythnet**, processing, and signing them.

---

## 🚀 Getting Started

### 🛠️ Build the Project

```bash
cargo build --release
```

Or for development:

```bash
cargo build
```

---

### ▶️ Run the Project

You can run the project using `cargo run` by passing the required flags:
Make sure to set `RUST_LOG=INFO` to enable logs from tracing:

```bash
RUST_LOG=INFO cargo run -- run \
  --pythnet-url wss://api2.pythnet.pyth.network \
  --server-url https://quorum-green.pyth.network \
  --server-url https://quorum-yellow.pyth.network \
  --server-url https://quorum-cyan.pyth.network \
  --secret-key /path/to/secret.key \
  --wormhole-pid H3fxXJ86ADW2PNuDDmZJg6mzTtPxkYCpNuQUTgmJ7AjU
```

You can specify multiple `--server-url` flags to broadcast observations to more than one server.


---

### 🌱 Environment Variables (Optional)

Instead of CLI flags, you can also set environment variables:

```bash
export PYTHNET_URL=wss://api2.pythnet.pyth.network
export SERVER_URL=https://quorum-green.pyth.network,https://quorum-yellow.pyth.network,https://quorum-cyan.pyth.network
export SECRET_KEY=/path/to/secret.key
export WORMHOLE_PID=H3fxXJ86ADW2PNuDDmZJg6mzTtPxkYCpNuQUTgmJ7AjU
export RUST_LOG=INFO

cargo run
```

You can provide multiple server URLs in the `SERVER_URL` environment variable by separating them with commas.

---

### 🔑 Generate a Secret Key

To generate a new secp256k1 secret key and write it to a file:

```bash
RUST_LOG=INFO cargo run -- generate-key --output-file .secret
```

This will save the key in raw byte format to the file named `.secret`.

---

### 🧪 Testing Locally

To test in a non-production environment (e.g. with devnet or a local Pythnet fork), just provide a different `--pythnet-url`, and `--server-url`, and optionally use custom `--wormhole-pid`.
