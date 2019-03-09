use generic_array::{GenericArray, ArrayLength};
use keystream::{KeyStream, SeekableKeyStream};
use abstract_cryptography::{PublicKey, SecretKey};
use crypto_mac::Mac;
use digest::{Input, FixedOutput};

pub trait PseudoRandomStream<T>
where
    T: ArrayLength<u8>,
{
    fn seed(v: GenericArray<u8, T>) -> Self;
}

pub trait Sphinx {
    type KeyLength: ArrayLength<u8>;
    type MacLength: ArrayLength<u8>;
    type AsymmetricKey: SecretKey;
    type Stream: KeyStream + SeekableKeyStream;
    type Collector;

    fn mu(shared: &GenericArray<u8, <Self::AsymmetricKey as SecretKey>::Length>) -> Self::Collector;

    fn chain<T>(collector: Self::Collector, data: T) -> Self::Collector
    where
        T: AsRef<[u8]>;

    fn output(collector: Self::Collector) -> GenericArray<u8, Self::MacLength>;

    fn rho(shared: &GenericArray<u8, <Self::AsymmetricKey as SecretKey>::Length>) -> Self::Stream;

    fn pi(shared: &GenericArray<u8, <Self::AsymmetricKey as SecretKey>::Length>) -> Self::Stream;

    fn tau(
        public_key: <Self::AsymmetricKey as SecretKey>::PublicKey,
    ) -> GenericArray<u8, <Self::AsymmetricKey as SecretKey>::Length>;

    fn blinding(
        public_key: &<Self::AsymmetricKey as SecretKey>::PublicKey,
        shared: &GenericArray<u8, <Self::AsymmetricKey as SecretKey>::Length>,
    ) -> GenericArray<u8, <Self::AsymmetricKey as SecretKey>::Length>;
}

impl<A, C, D, S> Sphinx for (A, C, D, S)
where
    A: SecretKey,
    C: Mac,
    D: Default + Input + FixedOutput<OutputSize = A::Length>,
    S: PseudoRandomStream<C::OutputSize> + SeekableKeyStream,
{
    type KeyLength = C::KeySize;
    type MacLength = C::OutputSize;
    type AsymmetricKey = A;
    type Stream = S;
    type Collector = C;

    fn mu(shared: &GenericArray<u8, <Self::AsymmetricKey as SecretKey>::Length>) -> Self::Collector {
        let mut collector = C::new_varkey(b"mu").unwrap();
        collector.input(shared);
        let key = collector.result().code();
        C::new_varkey(&key).unwrap()
    }

    fn chain<T>(collector: Self::Collector, data: T) -> Self::Collector
    where
        T: AsRef<[u8]>,
    {
        let mut collector = collector;
        Mac::input(&mut collector, data.as_ref());
        collector
    }

    fn output(collector: Self::Collector) -> GenericArray<u8, Self::MacLength> {
        Mac::result(collector).code()
    }

    fn rho(shared: &GenericArray<u8, <Self::AsymmetricKey as SecretKey>::Length>) -> Self::Stream {
        let mut collector = C::new_varkey(b"rho").unwrap();
        collector.input(shared);
        let key = collector.result().code();
        S::seed(key)
    }

    fn pi(shared: &GenericArray<u8, <Self::AsymmetricKey as SecretKey>::Length>) -> Self::Stream {
        let mut collector = C::new_varkey(b"um").unwrap();
        collector.input(shared);
        let key = collector.result().code();
        S::seed(key)
    }

    fn tau(
        public_key: <Self::AsymmetricKey as SecretKey>::PublicKey,
    ) -> GenericArray<u8, <Self::AsymmetricKey as SecretKey>::Length> {
        D::default()
            .chain(&public_key.serialize()[..])
            .fixed_result()
    }

    fn blinding(
        public_key: &<Self::AsymmetricKey as SecretKey>::PublicKey,
        shared: &GenericArray<u8, <Self::AsymmetricKey as SecretKey>::Length>,
    ) -> GenericArray<u8, <Self::AsymmetricKey as SecretKey>::Length> {
        D::default()
            .chain(&public_key.serialize()[..])
            .chain(shared)
            .fixed_result()
    }
}