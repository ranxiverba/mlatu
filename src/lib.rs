#![forbid(unsafe_code)]
#![allow(non_shorthand_field_patterns)]

#[cfg(test)]
mod test;

use abstract_cryptography::{SecretKey, PublicKey};
use digest::{Input, FixedOutput, BlockInput, Reset};
use generic_array::{GenericArray, ArrayLength};
use keystream::{KeyStream, SeekableKeyStream};
use std::ops::BitXorAssign;
use abstract_cryptography::TagError;
use either::Either;
use abstract_cryptography::Array;

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
    pub fn new<T, H, D, S>(version: OnionPacketVersion, session_key: A, route: H, associated_data: T) -> Result<Self, A::Error>
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

        payloads
            .into_iter()
            .enumerate()
            .rev()
            .for_each(|(index, payload)| {
                let rho = KeyType::Rho.key::<_, D>(&shared_secrets[index]);
                let mut stream = S::seed(rho);

                for i in (1..MAX_HOPS_NUMBER).rev() {
                    routing_info[i].data = routing_info[i - 1].data.clone();
                    routing_info[i].hmac = routing_info[i - 1].hmac.clone();
                }
                routing_info[0] = PayloadHmac {
                    data: payload,
                    hmac: hmac.clone(),
                };

                routing_info.iter_mut().for_each(|x| *x ^= &mut stream);

                // first iteration
                let length = shared_secrets.len();
                if index == length - 1 {
                    for i in (MAX_HOPS_NUMBER - length + 1)..MAX_HOPS_NUMBER {
                        routing_info[i] = PayloadHmac::zero();
                    }
                    for i in 1..length {
                        let rho = KeyType::Rho.key::<_, D>(&shared_secrets[i - 1]);
                        let mut s = S::seed(rho);
                        let size = PayloadHmac::<L, D::OutputSize>::size();
                        s.seek_to((size * (MAX_HOPS_NUMBER - (i - 1))) as _).unwrap();
                        for j in 0..i {
                            routing_info[j + (MAX_HOPS_NUMBER - (length - 1))] ^= &mut s;
                        }
                    }
                }

                use hmac::{Mac, Hmac};
                let mu = KeyType::Mu.key::<_, D>(&shared_secrets[index]);
                let mac = Hmac::<D>::new_varkey(&mu).unwrap();
                let mut mac = routing_info.iter().fold(mac, |mut mac, hop| {
                    mac.input(&hop.data);
                    mac.input(&hop.hmac);
                    mac
                });
                mac.input(associated_data.as_ref());
                hmac = mac.result().code();
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

        use hmac::{Mac, Hmac};
        let mu = KeyType::Mu.key::<_, D>(&shared_secret);
        let mac = Hmac::<D>::new_varkey(&mu).unwrap();
        let mut mac = routing_info.iter().fold(mac, |mut mac, hop| {
            mac.input(&hop.data);
            mac.input(&hop.hmac);
            mac
        });
        mac.input(associated_data.as_ref());
        let hmac_received = mac.result().code();

        if hmac_received != hmac {
            Err(Either::Right(TagError))
        } else {
            let rho = KeyType::Rho.key::<_, D>(&shared_secret);
            let mut stream = S::seed(rho);

            let mut routing_info_extended = routing_info.to_vec();
            routing_info_extended.push(PayloadHmac::<L, M>::zero());
            routing_info_extended
                .iter_mut()
                .for_each(|x| *x ^= &mut stream);

            let PayloadHmac {
                data: output,
                hmac: hmac,
            } = routing_info_extended.remove(0);

            if hmac == GenericArray::default() {
                Ok(Processed::ExitNode { output: output })
            } else {
                let mut route = zero_path();
                route[..].clone_from_slice(routing_info_extended.as_slice());

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
                        routing_info: route,
                        hmac: hmac,
                    },
                    output: output,
                })
            }
        }
    }
}
