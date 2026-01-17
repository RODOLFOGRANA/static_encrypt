#[macro_use]
extern crate static_encrypt;

set_crypt!();

#[test]
fn basic_ascii() {
    let plain = "Hello World";
    let enc = enc!("Hello World");
    assert_eq!(plain, enc);
}

#[test]
fn json_raw_string() {
    let json = r#"{"status": "ok", "code": 200}"#;
    let enc = enc!(r#"{"status": "ok", "code": 200}"#);
    assert_eq!(json, enc);
}

#[test]
fn japanese_kanji_hiragana() {
    let plain = "こんにちは世界"; 
    let enc = enc!("こんにちは世界");
    assert_eq!(plain, enc);
}

#[test]
fn chinese_simplified() {
    let plain = "加密很有趣";
    let enc = enc!("加密很有趣");
    assert_eq!(plain, enc);
}

#[test]
fn russian_cyrillic() {
    let plain = "Rust - это быстро";
    let enc = enc!("Rust - это быстро");
    assert_eq!(plain, enc);
}

#[test]
fn robust_special_chars() {
    let plain = "Key: !@#$%^&*()_+|~=`{}[]:\";'<>?,./ ⚠️";
    let enc_simple = enc!("Key: !@#$%^&*()_+|~=`{}[]:\";'<>?,./ ⚠️");
    assert_eq!(plain, enc_simple);
}

#[test]
fn mixed_languages() {
    let plain = "Hello - こんにちは - 你好 - Привет";
    let enc = enc!("Hello - こんにちは - 你好 - Привет");
    assert_eq!(plain, enc);
}