use atomcrypte::{AtomCrypte, Config, Nonce, Rng};

fn main() {
    let nonce = Nonce::nonce(Rng::osrng());
    let data = b"Hellow, world!";
    let password = "super";

    let config = Config::default();

    let encrypted = AtomCrypte::encrypt(password, data, nonce, config).unwrap();
    let out = AtomCrypte::decrypt(password, &encrypted, nonce, config).unwrap();

    println!("Out: {}", String::from_utf8_lossy(&out))
}
