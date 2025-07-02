#[cfg(feature = "base_coding")]
use base64::{Engine, prelude::BASE64_STANDARD};

pub trait AsBase {
    #[cfg(feature = "base_coding")]
    fn as_base64(&self) -> String;
    fn as_string(&self) -> String;
}

impl AsBase for Vec<u8> {
    #[cfg(feature = "base_coding")]
    fn as_base64(&self) -> String {
        BASE64_STANDARD.encode(self)
    }

    fn as_string(&self) -> String {
        String::from_utf8_lossy(self).to_string()
    }
}
