use atomcrypte::{AtomCrypte, Config, Nonce, Rng};

fn main() {
    let nonce = Nonce::nonce(Rng::osrng());
    let data = b"Hello, world!";
    let password = "super";

    let config = Config::from_profile(atomcrypte::Profile::Secure);

    let encrypted = AtomCrypteBuilder::new()
        .nonce(nonce)
        .password(password.as_str())
        .data(data)
        .config(config)
        .encrypt()
        .unwrap();

    let out = AtomCrypteBuilder::new()
        .nonce(nonce)
        .password(password.as_str())
        .data(&encrypted)
        .config(config)
        .decrypt()
        .unwrap();

    println!("Out: {}", String::from_utf8_lossy(&out))
}
