use atomcrypte::{AtomCrypteBuilder, Config, MachineRng, Nonce, Rng};

fn main() {
    let nonce = Nonce::machine_nonce(Some(Rng::osrng()));
    let data = b"Hello, world!";
    let password = "super".machine_rng();

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

    println!("Decrypted: {}", String::from_utf8_lossy(&out));
}
