use atomcrypte::{AtomCrypte, Config, MachineRng, Nonce, Rng};

fn main() {
    let nonce = Nonce::nonce(Rng::osrng());
    let data = b"Hello, world!";
    let password = "super".machine_rng();
    let password = password.as_str();

    let config = Config::default();

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
