use generic_array::{GenericArray, ArrayLength};
use digest::{Input, FixedOutput, BlockInput, Reset};

pub enum KeyType {
    Rho,
    Mu,
}

impl KeyType {
    pub fn key<T, D>(&self, input: T) -> GenericArray<u8, D::OutputSize>
    where
        T: AsRef<[u8]>,
        D: Input + FixedOutput + BlockInput + Reset + Clone + Default,
        D::BlockSize: ArrayLength<u8> + Clone,
        D::OutputSize: ArrayLength<u8>,
    {
        use hmac::{Mac, Hmac};

        let key_type = match self {
            &KeyType::Rho => "rho",
            &KeyType::Mu => "mu",
        };

        let mut mac = Hmac::<D>::new_varkey(key_type.as_bytes()).unwrap();
        mac.input(input.as_ref());
        mac.result().code()
    }
}
