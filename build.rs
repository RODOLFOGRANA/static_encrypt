use rand::{rngs::OsRng, TryRngCore};

fn main() {
    // gen random key on compile time
    let mut key = [0u8; 64];
    OsRng.try_fill_bytes(&mut key).unwrap();

    let key_string = key
        .iter()
        .map(|b| b.to_string())
        .collect::<Vec<String>>()
        .join(",");

    println!("cargo:rustc-env=LITCRYPT_KEY={}", key_string);

    println!("cargo:rerun-if-changed=build.rs");
}
