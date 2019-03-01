use abstract_cryptography::{Array, SecretKey, PublicKey};
use digest::{Input, FixedOutput};
use generic_array::{GenericArray, ArrayLength};

#[derive(Debug, Eq, PartialEq)]
pub enum OnionPacketVersion {
    _0 = 0,
}

pub trait Hop {
    type PublicKey: PublicKey;

    fn id(&self) -> Self::PublicKey;
}

pub struct OnionPacketDescription<A, H, D, T>
where
    A: SecretKey,
    H: Iterator<Item = (A::PublicKey, D)>,
    D: Array,
    T: AsRef<[u8]>,
{
    version: OnionPacketVersion,
    session_key: A,
    route: H,
    associated_data: T,
}

impl<A, H, D, T> OnionPacketDescription<A, H, D, T>
where
    A: SecretKey + Clone,
    H: Iterator<Item = (A::PublicKey, D)>,
    D: Array,
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

    pub fn packet<M>(self) -> OnionPacket<A, D, M>
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
                    let mut c = D::default();
                    c.input(&temp.serialize()[..]);
                    let result = c.fixed_result();
                    let mut c = D::default();
                    c.input(&public.serialize()[..]);
                    c.input(&result);
                    let blinding = c.fixed_result();
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

pub struct OnionPacket<A, D, M>
where
    A: SecretKey,
    D: Array,
    M: Array,
{
    version: OnionPacketVersion,
    ephemeral_public_key: A::PublicKey,
    routing_info: [(D, M); MAX_HOPS_NUMBER],
    hmac: M,
}

pub enum Processed<A, D, M>
where
    A: SecretKey,
    D: Array,
    M: Array,
{
    ExitNode,
    MoreHops {
        next: OnionPacket<A, D, M>,
        forwarding_instructions: D,
    },
}

impl<A, D, M> OnionPacket<A, D, M>
where
    A: SecretKey,
    D: Array,
    M: Array,
{
    pub fn process<T>(self, associated_data: T, secret_key: A) -> Processed<A, D, M>
    where
        T: AsRef<[u8]>,
    {
        let _ = (associated_data, secret_key);
        unimplemented!()
    }
}
