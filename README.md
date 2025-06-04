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

```bash
cargo run -- \
  --pythnet-url wss://api2.pythnet.pyth.network \
  --server-url https://watcher.pyth.network \
  --secret-key /path/to/secret.key \
  --wormhole-pid H3fxXJ86ADW2PNuDDmZJg6mzTtPxkYCpNuQUTgmJ7AjU
```

---

### 🌱 Environment Variables (Optional)

Instead of CLI flags, you can also set environment variables:

```bash
export PYTHNET_URL=wss://api2.pythnet.pyth.network
export SERVER_URL=https://watcher.pyth.network
export SECRET_KEY=/path/to/secret.key
export WORMHOLE_PID=H3fxXJ86ADW2PNuDDmZJg6mzTtPxkYCpNuQUTgmJ7AjU

cargo run
```

---

### 🧪 Testing Locally

To test in a non-production environment (e.g. with devnet or a local Pythnet fork), just provide a different `--pythnet-url`, and `--server-url`, and optionally use custom `--wormhole-pid`.
