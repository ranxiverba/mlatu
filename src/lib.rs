#![forbid(unsafe_code)]
#![allow(non_shorthand_field_patterns)]

#[cfg(test)]
mod test;

use abstract_cryptography::{Array, SecretKey, PublicKey, TagError};
use digest::{Input, FixedOutput, BlockInput, Reset};
use generic_array::{GenericArray, ArrayLength};
use keystream::{KeyStream, SeekableKeyStream};
use std::ops::BitXorAssign;
use either::Either;

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

pub trait PseudoRandomStream {
    fn seed<T>(v: T) -> Self
    where
        T: AsRef<[u8]>;
}

const MAX_HOPS_NUMBER: usize = 20;

#[derive(Clone, Default)]
struct PayloadHmac<L, M>
where
    L: ArrayLength<u8>,
    M: ArrayLength<u8>,
{
    data: GenericArray<u8, L>,
    hmac: GenericArray<u8, M>,
}

impl<L, M> PayloadHmac<L, M>
where
    L: ArrayLength<u8>,
    M: ArrayLength<u8>,
{
    fn zero() -> Self {
        PayloadHmac {
            data: Default::default(),
            hmac: Default::default(),
        }
    }

    fn size() -> usize {
        L::to_usize() + M::to_usize()
    }
}

impl<'a, L, M, I> BitXorAssign<&'a mut I> for PayloadHmac<L, M>
where
    L: ArrayLength<u8>,
    M: ArrayLength<u8>,
    I: KeyStream,
{
    fn bitxor_assign(&mut self, rhs: &'a mut I) {
        rhs.xor_read(self.data.as_mut_slice()).unwrap();
        rhs.xor_read(self.hmac.as_mut_slice()).unwrap();
    }
}

fn calc_hmac<L, D, T>(
    v: &[PayloadHmac<L, D::OutputSize>; MAX_HOPS_NUMBER],
    mu: &GenericArray<u8, D::OutputSize>,
    associated_data: T
) -> GenericArray<u8, D::OutputSize>
where
    L: ArrayLength<u8>,
    D: Input + FixedOutput + BlockInput + Reset + Clone + Default,
    D::BlockSize: ArrayLength<u8> + Clone,
    D::OutputSize: ArrayLength<u8>,
    T: AsRef<[u8]>,
{
    use hmac::{Mac, Hmac};

    let mac = Hmac::<D>::new_varkey(&mu).unwrap();
    let mut mac = v.iter().fold(mac, |mut mac, hop| {
        mac.input(&hop.data);
        mac.input(&hop.hmac);
        mac
    });
    mac.input(associated_data.as_ref());
    mac.result().code()
}

fn zero_path<L, M>() -> [PayloadHmac<L, M>; MAX_HOPS_NUMBER]
where
    L: ArrayLength<u8>,
    M: ArrayLength<u8>,
{
    [
        PayloadHmac::<L, M>::zero(),
        PayloadHmac::<L, M>::zero(),
        PayloadHmac::<L, M>::zero(),
        PayloadHmac::<L, M>::zero(),
        PayloadHmac::<L, M>::zero(),
        PayloadHmac::<L, M>::zero(),
        PayloadHmac::<L, M>::zero(),
        PayloadHmac::<L, M>::zero(),
        PayloadHmac::<L, M>::zero(),
        PayloadHmac::<L, M>::zero(),
        PayloadHmac::<L, M>::zero(),
        PayloadHmac::<L, M>::zero(),
        PayloadHmac::<L, M>::zero(),
        PayloadHmac::<L, M>::zero(),
        PayloadHmac::<L, M>::zero(),
        PayloadHmac::<L, M>::zero(),
        PayloadHmac::<L, M>::zero(),
        PayloadHmac::<L, M>::zero(),
        PayloadHmac::<L, M>::zero(),
        PayloadHmac::<L, M>::zero(),
    ]
}

pub struct OnionPacket<A, L, M>
where
    A: SecretKey,
    L: ArrayLength<u8>,
    M: ArrayLength<u8>,
{
    version: OnionPacketVersion,
    ephemeral_public_key: A::PublicKey,
    routing_info: [PayloadHmac<L, M>; MAX_HOPS_NUMBER],
    hmac: GenericArray<u8, M>,
}

pub enum Processed<A, L, M>
where
    A: SecretKey,
    L: ArrayLength<u8>,
    M: ArrayLength<u8>,
{
    ExitNode {
        output: GenericArray<u8, L>,
    },
    MoreHops {
        next: OnionPacket<A, L, M>,
        output: GenericArray<u8, L>,
    },
}

impl<A, L, M> OnionPacket<A, L, M>
where
    A: SecretKey + Clone + Array,
    A::PublicKey: Clone,
    L: ArrayLength<u8> + Clone,
    M: ArrayLength<u8> + Clone,
{
    pub fn new<T, H, D, S>(
        version: OnionPacketVersion,
        session_key: A,
        route: H,
        associated_data: T,
    ) -> Result<Self, A::Error>
    where
        T: AsRef<[u8]>,
        H: Iterator<Item = (A::PublicKey, GenericArray<u8, L>)>,
        D: Input + FixedOutput<OutputSize = M> + BlockInput + Reset + Clone + Default,
        D::BlockSize: ArrayLength<u8> + Clone,
        D::OutputSize: ArrayLength<u8>,
        S: PseudoRandomStream + SeekableKeyStream,
    {
        let base_point = A::PublicKey::base_point();
        let contexts = A::contexts();
        let public_key = session_key.paired(&contexts.0);

        let initial = (
            Vec::new(),
            Vec::new(),
            session_key.clone(),
            public_key.clone(),
        );

        let mut route = route;
        let (shared_secrets, payloads) = route
            .try_fold(
                initial,
                |(mut s, mut p, mut secret, public), (path_point, payload)| {
                    let temp = secret.dh(&contexts.1, &path_point)?;
                    let result = D::default().chain(&temp.serialize()[..]).fixed_result();
                    let blinding = D::default()
                        .chain(&public.serialize()[..])
                        .chain(&result)
                        .fixed_result();
                    secret.mul_assign(&blinding)?;
                    let public = secret.dh(&contexts.1, &base_point)?;

                    s.push(result);
                    p.push(payload);
                    Ok((s, p, secret, public))
                },
            )
            .map(|(s, p, _, _)| (s, p))?;

        let mut hmac = GenericArray::<u8, D::OutputSize>::default();
        let mut routing_info = zero_path::<L, D::OutputSize>();

        let length = shared_secrets.len();
        for i in 0..length {
            let rho = KeyType::Rho.key::<_, D>(&shared_secrets[i]);
            let mut s = S::seed(rho);
            let size = PayloadHmac::<L, D::OutputSize>::size();
            s.seek_to((size * (MAX_HOPS_NUMBER - i)) as _).unwrap();
            let start = MAX_HOPS_NUMBER - length;
            routing_info[start..(start + i + 1)].iter_mut().for_each(|x| *x ^= &mut s);
        }

        payloads
            .into_iter()
            .enumerate()
            .rev()
            .for_each(|(index, payload)| {
                // shift right and place payload at 0
                for i in (1..MAX_HOPS_NUMBER).rev() {
                    routing_info[i] = routing_info[i - 1].clone();
                }
                routing_info[0] = PayloadHmac {
                    data: payload,
                    hmac: hmac.clone(),
                };

                let rho = KeyType::Rho.key::<_, D>(&shared_secrets[index]);
                let mut stream = S::seed(rho);
                routing_info.iter_mut().for_each(|x| *x ^= &mut stream);

                let mu = KeyType::Mu.key::<_, D>(&shared_secrets[index]);
                hmac = calc_hmac::<L, D, _>(&routing_info, &mu, &associated_data);
            });

        Ok(OnionPacket {
            version: version,
            ephemeral_public_key: public_key,
            routing_info: routing_info,
            hmac: hmac,
        })
    }

    pub fn process<T, S, D>(
        self,
        associated_data: T,
        secret_key: A,
    ) -> Result<Processed<A, L, M>, Either<A::Error, TagError>>
    where
        T: AsRef<[u8]>,
        S: PseudoRandomStream + SeekableKeyStream,
        D: Input + FixedOutput<OutputSize = M> + BlockInput + Reset + Clone + Default,
        D::BlockSize: ArrayLength<u8> + Clone,
    {
        let contexts = A::contexts();

        let public_key = self.ephemeral_public_key;
        let temp = secret_key
            .dh(&contexts.1, &public_key)
            .map_err(Either::Left)?;
        let shared_secret = D::default().chain(temp.serialize()).fixed_result();

        let (version, routing_info, hmac) = (self.version, self.routing_info, self.hmac);

        let mu = KeyType::Mu.key::<_, D>(&shared_secret);
        let hmac_received = calc_hmac::<L, D, _>(&routing_info, &mu, associated_data);

        if hmac_received != hmac {
            Err(Either::Right(TagError))
        } else {
            let rho = KeyType::Rho.key::<_, D>(&shared_secret);
            let mut stream = S::seed(rho);

            let mut routing_info = routing_info;
            routing_info
                .iter_mut()
                .for_each(|x| *x ^= &mut stream);

            let PayloadHmac {
                data: output,
                hmac: hmac,
            } = routing_info[0].clone();

            for i in 1..MAX_HOPS_NUMBER {
                routing_info[i - 1] = routing_info[i].clone();
            }
            routing_info[MAX_HOPS_NUMBER - 1] = PayloadHmac::zero();
            routing_info[MAX_HOPS_NUMBER - 1] ^= &mut stream;

            if hmac == GenericArray::default() {
                Ok(Processed::ExitNode { output: output })
            } else {
                let dh_key = public_key;
                let blinding = D::default()
                    .chain(dh_key.serialize())
                    .chain(shared_secret)
                    .fixed_result();
                let next_dh_key = A::copy(blinding)
                    .dh(&contexts.1, &dh_key)
                    .map_err(Either::Left)?;

                Ok(Processed::MoreHops {
                    next: OnionPacket {
                        version: version,
                        ephemeral_public_key: next_dh_key,
                        routing_info: routing_info,
                        hmac: hmac,
                    },
                    output: output,
                })
            }
        }
    }
}
