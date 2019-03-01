use abstract_cryptography::{Array, SecretKey, PublicKey};
use digest::{Input, FixedOutput, BlockInput, Reset};
use generic_array::{GenericArray, ArrayLength};

#[derive(Debug, Eq, PartialEq)]
pub enum OnionPacketVersion {
    _0 = 0,
}

enum KeyType {
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

pub struct OnionPacketDescription<A, H, L, T>
where
    A: SecretKey,
    H: Iterator<Item = (A::PublicKey, GenericArray<u8, L>)>,
    L: ArrayLength<u8>,
    T: AsRef<[u8]>,
{
    version: OnionPacketVersion,
    session_key: A,
    route: H,
    associated_data: T,
}

impl<A, H, L, T> OnionPacketDescription<A, H, L, T>
where
    A: SecretKey + Clone,
    H: Iterator<Item = (A::PublicKey, GenericArray<u8, L>)>,
    L: ArrayLength<u8>,
    T: AsRef<[u8]>,
{
    pub fn new(version: OnionPacketVersion, session_key: A, route: H, associated_data: T) -> Self {
        OnionPacketDescription {
            version: version,
            session_key: session_key,
            route: route,
            associated_data: associated_data,
        }
    }

    pub fn packet<M>(self) -> OnionPacket<A, L, M>
    where
        M: Array,
    {
        fn generate_shared_secrets<A, I, D>(
            path: I,
            session_key: &A,
        ) -> Result<Vec<GenericArray<u8, D::OutputSize>>, A::Error>
        where
            A: SecretKey + Clone,
            I: Iterator<Item = A::PublicKey>,
            D: Input + FixedOutput + Default,
            D::OutputSize: ArrayLength<u8>,
        {
            let base_point = A::PublicKey::base_point();
            let contexts = A::contexts();

            let initial = (
                Vec::new(),
                session_key.clone(),
                session_key.paired(&contexts.0),
            );

            let mut path = path;
            path
                .try_fold(initial, |(mut v, mut secret, public), path_point| {
                    let temp = secret.dh(&contexts.1, &path_point)?;
                    let result = D::default()
                        .chain(&temp.serialize()[..]).fixed_result();
                    let blinding = D::default()
                        .chain(&public.serialize()[..]).chain(&result).fixed_result();
                    secret.mul_assign(&blinding)?;
                    let public = secret.dh(&contexts.1, &base_point)?;

                    v.push(result);
                    Ok((v, secret, public))
                }).map(|(v, _, _)| v)
        }

        unimplemented!()
    }
}

pub const MAX_HOPS_NUMBER: usize = 20;

pub struct OnionPacket<A, L, M>
where
    A: SecretKey,
    L: ArrayLength<u8>,
    M: Array,
{
    version: OnionPacketVersion,
    ephemeral_public_key: A::PublicKey,
    routing_info: [(GenericArray<u8, L>, M); MAX_HOPS_NUMBER],
    hmac: M,
}

pub enum Processed<A, L, M>
where
    A: SecretKey,
    L: ArrayLength<u8>,
    M: Array,
{
    ExitNode,
    MoreHops {
        next: OnionPacket<A, L, M>,
        output: GenericArray<u8, L>,
    },
}

impl<A, L, M> OnionPacket<A, L, M>
where
    A: SecretKey,
    L: ArrayLength<u8>,
    M: Array,
{
    pub fn process<T>(self, associated_data: T, secret_key: A) -> Processed<A, L, M>
    where
        T: AsRef<[u8]>,
    {
        let _ = (associated_data, secret_key);
        unimplemented!()
    }
}
