# Static Encrypt

**Protect your strings from static analysis tools.**

`static_encrypt` is a Rust proc-macro crate that encrypts string literals at **compile time**. The plain text strings never appear in your compiled binary. They are encrypted using a **unique, random key generated during every build**, and only decrypted at runtime when needed.

This crate is a modernized and advanced version, featuring 6 different encryption algorithms and automatic key management.

## Features

* **Compile-Time Encryption:** Strings are encrypted before they ever reach the binary.
* **Unique Random Keys:** A fresh random key is generated automatically via `build.rs` every time you compile. No need to manage environment variables manually.
* **6 Encryption Algorithms:** Choose the balance of speed and obfuscation that fits your needs.
* **Zero Dependencies (Runtime):** Extremely lightweight runtime footprint.
* **UTF-8 Support:** Full support for Emoji, CJK (Chinese/Japanese/Korean), and Cyrillic characters.

## Installation

```bash
cargo add static_encrypt
```

(or)

Add this to your `Cargo.toml`:

```toml
[dependencies]
static_encrypt = "0.1.0"
```

## Usage

Example: 

```rust
#[macro_use]
extern crate static_encrypt;

// Initialize the decryption runtime. 
// This injects the decryption code specific to your selected algorithm.
set_crypt!();

fn main() {
    // Use enc!() to encrypt strings.
    let message = enc!("This is a secret message");
    
    println!("Message: {}", message);
}
```

Real Example:

```rust
#[macro_use]
extern crate static_encrypt;

set_crypt!();

use reqwest::header::{AUTHORIZATION, HeaderValue};
use reqwest::Client;
use std::env;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {

    let enc_key = 
    let api_key = std::env::var(enc!("TEST"))
        .expect("MY_API_KEY not set in environment variables");

    let client = Client::new();
    let url = enc!("https://api.example.com/data");

    let response = client.get(url)
        .header(AUTHORIZATION, format!("Bearer {}", api_key))
        .send()
        .await?
        .text()
        .await?;

    println!("Response: {}", response);

    Ok(())
}

```

### 2. Switching Algorithms

You can change the underlying encryption algorithm using **Cargo Features**. The default is `xor`.

To use **RC4** (Stream Cipher):

```toml
[dependencies]
static_encrypt = { version = "0.1.0", features = ["rc4"] }

```

To use **XorR** (Rolling Key XOR - harder to crack):

```toml
[dependencies]
static_encrypt = { version = "0.1.0", features = ["xorr"] }

```

## Supported Algorithms

Select one via `features` in `Cargo.toml`.

| Feature | Algorithm | Description | Strength |
| --- | --- | --- | --- |
| **`xor`** | **XOR (Default)** | Classic repeating-key XOR. | Low (Fastest) |
| `rc4` | **RC4** | Rivest Cipher 4 (Stream Cipher). | Medium |
| `xorshift` | **XorShift** | Uses a Pseudo-Random Number Generator (PRNG) as a keystream. | Medium |
| `xorr` | **Rolling XOR** | Key bits rotate/roll after every byte. Prevents simple frequency analysis. | Medium-High |
| `vigenere` | **Vigenère** | Polyalphabetic substitution (Addition/Subtraction). | Low |
| `lcg` | **LCG** | Linear Congruential Generator stream. | Low-Medium |

## How It Works

1. **Build Script (`build.rs`):** When you run `cargo build`, this script runs first. It generates a high-entropy random key (64 bytes) and saves it into the compilation environment.
2. **Macro Expansion:** The `enc!("string")` macro reads this key, encrypts your string using the selected algorithm (e.g., RC4), and replaces your string with a byte array: `[23, 114, 210, ...]`.
3. **Runtime:** The `set_crypt!()` macro injects a tiny decryptor function. When your program runs, it takes the byte array and decrypts it back to a string in memory.

## License

- Apache License, Version 2.0, ([LICENSE-APACHE](./LICENSE-APACHE) or
  <https://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](./LICENSE-MIT) or <https://opensource.org/licenses/MIT>)

