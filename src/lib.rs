// Smukx.E (@5mukx)

extern crate proc_macro;
use proc_macro::{TokenStream, TokenTree};
use quote::{quote};
use proc_macro2::{Literal};

fn get_compile_time_key() -> Vec<u8> {
    let key_str = env!("LITCRYPT_KEY"); 
    key_str.split(',')
        .map(|s| s.parse::<u8>().expect("Failed to parse key from build.rs"))
        .collect()
}

#[proc_macro]
pub fn set_crypt(_input: TokenStream) -> TokenStream {
    let decrypt_code = if cfg!(feature = "rc4") {
        emit_rc4_decrypt()
    } else if cfg!(feature = "xorshift") {
        emit_xorshift_decrypt()
    } else if cfg!(feature = "vigenere") {
        emit_vigenere_decrypt()
    } else if cfg!(feature = "lcg") {
        emit_lcg_decrypt()
    } else if cfg!(feature = "xorr") {
        emit_xorr_decrypt()
    } else {
        emit_xor_decrypt()
    };

    let master_key = get_compile_time_key();
    let master_key_enc = encrypt_xor(&master_key, b"code/rustc/e5b2d8f9a1c3049687db03746cdf8af4d86e9ca4/library/alloc/src/vec/mod.rs");
    let master_key_lit = Literal::byte_string(&master_key_enc);

    quote! {
        pub mod litcrypt_internal {
            pub fn decrypt_final(encrypted: &[u8]) -> String {
                let key_enc = #master_key_lit;
                
                // Confuse while analysis =) 
                let master_key = decrypt_xor_internal(key_enc, b"code/rustc/e5b2d8f9a1c3049687db03746cdf8af4d86e9ca4/library/alloc/src/vec/mod.rs");
                let decrypted_bytes = decrypt_bytes(encrypted, &master_key);
                String::from_utf8(decrypted_bytes).unwrap_or(String::from("???"))
            }

            fn decrypt_xor_internal(source: &[u8], key: &[u8]) -> Vec<u8> {
                let mut out = Vec::with_capacity(source.len());
                for (i, byte) in source.iter().enumerate() {
                    out.push(byte ^ key[i % key.len()]);
                }
                out
            }

            #decrypt_code
        }
    }.into()
}

#[proc_macro]
pub fn enc(tokens: TokenStream) -> TokenStream {
    let mut input_str = String::new();
    for tok in tokens {
        if let TokenTree::Literal(lit) = tok {
            let s = lit.to_string();
            
            if s.starts_with("r") {
                if let Some(start_quote) = s.find('"') {
                    let num_hashes = start_quote - 1; 
                    let end_quote = s.len() - 1 - num_hashes;
                    input_str = s[start_quote + 1..end_quote].to_string();
                }
            } else if s.starts_with('"') {
                input_str = s.trim_matches('"').to_string();
                
                input_str = input_str.replace("\\\"", "\"").replace("\\\\", "\\");
            } else {
                input_str = s;
            }
        }
    }

    let key = get_compile_time_key();

    let encrypted_bytes = if cfg!(feature = "rc4") {
        encrypt_rc4(input_str.as_bytes(), &key)
    } else if cfg!(feature = "xorshift") {
        encrypt_xorshift(input_str.as_bytes(), &key)
    } else if cfg!(feature = "vigenere") {
        encrypt_vigenere(input_str.as_bytes(), &key)
    } else if cfg!(feature = "lcg") {
        encrypt_lcg(input_str.as_bytes(), &key)
    } else if cfg!(feature = "xorr") {
        encrypt_xorr(input_str.as_bytes(), &key)
    } else {
        encrypt_xor(input_str.as_bytes(), &key)
    };

    let bytes_lit = Literal::byte_string(&encrypted_bytes);

    quote! {
        crate::litcrypt_internal::decrypt_final(#bytes_lit)
    }.into()
}

// encryption algorithm starts here .....
fn encrypt_xor(source: &[u8], key: &[u8]) -> Vec<u8> {
    source.iter().enumerate().map(|(i, b)| b ^ key[i % key.len()]).collect()
}

fn emit_xor_decrypt() -> proc_macro2::TokenStream {
    quote! {
        fn decrypt_bytes(source: &[u8], key: &[u8]) -> Vec<u8> {
            let mut out = Vec::with_capacity(source.len());
            for (i, byte) in source.iter().enumerate() {
                out.push(byte ^ key[i % key.len()]);
            }
            out
        }
    }
}

fn encrypt_rc4(data: &[u8], key: &[u8]) -> Vec<u8> {
    let mut s: [u8; 256] = [0; 256];
    let mut j: usize = 0;
    for i in 0..=255 { s[i] = i as u8; }
    for i in 0..=255 {
        j = (j + s[i] as usize + key[i % key.len()] as usize) % 256;
        s.swap(i, j);
    }
    let mut i = 0; j = 0;
    let mut out = Vec::new();
    for &b in data {
        i = (i + 1) % 256;
        j = (j + s[i] as usize) % 256;
        s.swap(i, j);
        let k = s[(s[i] as usize + s[j] as usize) % 256];
        out.push(b ^ k);
    }
    out
}
fn emit_rc4_decrypt() -> proc_macro2::TokenStream {
    quote! {
        fn decrypt_bytes(data: &[u8], key: &[u8]) -> Vec<u8> {
            let mut s: [u8; 256] = [0; 256];
            let mut j: usize = 0;
            for i in 0..=255 { s[i] = i as u8; }
            for i in 0..=255 {
                j = (j + s[i] as usize + key[i % key.len()] as usize) % 256;
                let tmp = s[i]; s[i] = s[j]; s[j] = tmp;
            }
            let mut i = 0; j = 0;
            let mut out = Vec::new();
            for &b in data {
                i = (i + 1) % 256;
                j = (j + s[i] as usize) % 256;
                let tmp = s[i]; s[i] = s[j]; s[j] = tmp;
                let k = s[(s[i] as usize + s[j] as usize) % 256];
                out.push(b ^ k);
            }
            out
        }
    }
}

fn encrypt_xorshift(data: &[u8], key: &[u8]) -> Vec<u8> {
    let mut seed: u32 = 0xCAFEBABE;
    for &b in key { seed = seed.wrapping_add(b as u32).wrapping_mul(0x9E3779B9); }
    if seed == 0 { seed = 0xDEADBEEF; }
    let mut out = Vec::new();
    let mut state = seed;
    for &b in data {
        let mut x = state;
        x ^= x << 13; x ^= x >> 17; x ^= x << 5;
        state = x;
        out.push(b ^ (state as u8));
    }
    out
}
fn emit_xorshift_decrypt() -> proc_macro2::TokenStream {
    quote! {
        fn decrypt_bytes(data: &[u8], key: &[u8]) -> Vec<u8> {
            let mut seed: u32 = 0xCAFEBABE;
            for &b in key { seed = seed.wrapping_add(b as u32).wrapping_mul(0x9E3779B9); }
            if seed == 0 { seed = 0xDEADBEEF; }
            let mut out = Vec::new();
            let mut state = seed;
            for &b in data {
                let mut x = state;
                x ^= x << 13; x ^= x >> 17; x ^= x << 5;
                state = x;
                out.push(b ^ (state as u8));
            }
            out
        }
    }
}


fn encrypt_vigenere(data: &[u8], key: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    for (i, &b) in data.iter().enumerate() {
        let k = key[i % key.len()];

        out.push(b.wrapping_add(k)); 
    }
    out
}
fn emit_vigenere_decrypt() -> proc_macro2::TokenStream {
    quote! {
        fn decrypt_bytes(data: &[u8], key: &[u8]) -> Vec<u8> {
            let mut out = Vec::new();
            for (i, &b) in data.iter().enumerate() {
                let k = key[i % key.len()];

                out.push(b.wrapping_sub(k));
            }
            out
        }
    }
}

fn encrypt_lcg(data: &[u8], key: &[u8]) -> Vec<u8> {
    let mut seed: u32 = 0;
    for &b in key { seed = seed.wrapping_add(b as u32); }
    
    let a: u32 = 1664525;
    let c: u32 = 1013904223;
    let mut state = seed;
    
    let mut out = Vec::new();
    for &b in data {
        state = state.wrapping_mul(a).wrapping_add(c);
        let pad = (state >> 24) as u8; 
        out.push(b ^ pad);
    }
    out
}

fn emit_lcg_decrypt() -> proc_macro2::TokenStream {
    quote! {
        fn decrypt_bytes(data: &[u8], key: &[u8]) -> Vec<u8> {
            let mut seed: u32 = 0;
            for &b in key { seed = seed.wrapping_add(b as u32); }
            
            let a: u32 = 1664525;
            let c: u32 = 1013904223;
            let mut state = seed;
            
            let mut out = Vec::new();
            for &b in data {
                state = state.wrapping_mul(a).wrapping_add(c);
                let pad = (state >> 24) as u8;
                out.push(b ^ pad);
            }
            out
        }
    }
}

fn encrypt_xorr(data: &[u8], key: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut rolling_key = key.to_vec();
    let len = rolling_key.len();

    for (i, &b) in data.iter().enumerate() {
        let idx = i % len;
        let k = rolling_key[idx];
        
        out.push(b ^ k);

        rolling_key[idx] = k.rotate_left(1);
    }
    out
}

fn emit_xorr_decrypt() -> proc_macro2::TokenStream {
    quote! {
        fn decrypt_bytes(data: &[u8], key: &[u8]) -> Vec<u8> {
            let mut out = Vec::new();
            let mut rolling_key = key.to_vec();
            let len = rolling_key.len();

            for (i, &b) in data.iter().enumerate() {
                let idx = i % len;
                let k = rolling_key[idx];
                
                out.push(b ^ k);

                rolling_key[idx] = k.rotate_left(1);
            }
            out
        }
    }
}