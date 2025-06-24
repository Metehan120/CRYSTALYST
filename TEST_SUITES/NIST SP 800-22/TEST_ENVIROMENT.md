# How to Reproduce the Encrypted Output
* All test artifacts, including output binaries, can be found in this directory. Feel free to re-run tests using official tools.
* You can use the following `main.rs` to reproduce the binary used in the NIST tests:
```rust
use std::{fs::File, io::Write};

use atomcrypte::{AtomCrypteBuilder, Config, Nonce, NonceType, Rng, Salt, Utils};

fn main() {
    let data = vec![0u8; 50_000_000];

    let key = "2~:i*'ldo`b7W_Av#gBd2w$+6V*!Id&(";

    let config = Config::default().argon2_type(atomcrypte::Argon2Type::Argon2d);

    let nonce = Nonce::generate_nonce(Some(Rng::osrng()), NonceType::Classic).unwrap();

    let salt = Salt::salt();

    let encrypted = AtomCrypteBuilder::new()
        .data(&data)
        .password(key)
        .config(config)
        .nonce(nonce)
        .salt(salt)
        .encrypt()
        .unwrap();

    File::create("output.bin")
        .unwrap()
        .write_all(&encrypted)
        .unwrap();
}
```
