use generic_array::GenericArray;
use crypto_mac::Mac;

pub enum KeyType {
    Rho,
    Mu,
}

impl KeyType {
    pub fn key<T, C>(&self, input: T) -> GenericArray<u8, C::OutputSize>
    where
        T: AsRef<[u8]>,
        C: Mac,
    {
        let key_type = match self {
            &KeyType::Rho => "rho",
            &KeyType::Mu => "mu",
        };

        let mut mac = C::new_varkey(key_type.as_bytes()).unwrap();
        mac.input(input.as_ref());
        mac.result().code()
    }
}
