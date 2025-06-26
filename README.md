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
  --server-url https://quorum.pyth.network \
  --signer-uri file:///path/to/secret.key \
  --wormhole-pid H3fxXJ86ADW2PNuDDmZJg6mzTtPxkYCpNuQUTgmJ7AjU
```

✅ **Note on `--signer-uri`:**  
This argument specifies the signer backend and is compatible with the formats supported by the [Wormhole Guardian Signer](https://github.com/wormhole-foundation/wormhole/blob/main/docs/guardian_signer.md).

**Supported schemes:**
- `file://<path-to-file>` — Load an **armored OpenPGP secp256k1 private key** from a file.
- `amazonkms://<key-id-or-arn>` — Use a key stored in AWS KMS. The key must support `ECDSA_SHA_256` and use the `ECC_SECG_P256K1` curve.

**Example using AWS KMS:**
```bash
--signer-uri amazonkms://arn:aws:kms:us-west-2:123456789012:key/abcde-1234-5678
```

---

### 🌱 Environment Variables (Optional)

Instead of CLI flags, you can also set environment variables:

```bash
export PYTHNET_URL=wss://api2.pythnet.pyth.network
export SERVER_URL=https://quorum.pyth.network
export SIGNER_URI=file:///path/to/secret.key
export WORMHOLE_PID=H3fxXJ86ADW2PNuDDmZJg6mzTtPxkYCpNuQUTgmJ7AjU
export RUST_LOG=INFO

cargo run
```

---

### 🔑 Generate a Secret Key

To generate a new **armored OpenPGP secp256k1 secret key** and write it to a file:

```bash
RUST_LOG=INFO cargo run -- generate-key --output-file .secret
```

This will save the key in raw byte format to the file named `.secret`.

---

### 🧪 Testing Locally

To test in a non-production environment (e.g. with devnet or a local Pythnet fork), just provide a different `--pythnet-url`, and `--server-url`, and optionally use custom `--wormhole-pid`.
