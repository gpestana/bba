use algebra::{to_bytes, ToBytes};

use algebra::curves::AffineCurve;

use serde::de::{Deserialize, Deserializer};
use serde::ser::{Serialize, SerializeStruct, Serializer};

impl<G: AffineCurve> Serialize for crate::bba::Params<G> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("Params", 3)?;
        let h = to_bytes!(self.h).map_err(serde::ser::Error::custom)?;
        state.serialize_field("h", &h)?;

        let endo = to_bytes!(self.endo).map_err(serde::ser::Error::custom)?;
        state.serialize_field("endo", &endo)?;

        let comm = to_bytes!(self.lagrange_commitments)
            .map_err(serde::ser::Error::custom)?;
        state.serialize_field("lagrange_commitments", &comm)?;

        state.end()
    }
}

impl<G: AffineCurve, Other: AffineCurve> Serialize for crate::bba::InitRequest<G, Other> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("InitRequest", 2)?;

        let acc = to_bytes!(self.acc).map_err(serde::ser::Error::custom)?;
        state.serialize_field("acc", &acc)?;

        // TODO: implement serilized/to_bytes for plonk_5_wires_protocol_dlog::prover::ProverProof
        //let proof = to_bytes!(self.proof).map_err(serde::ser::Error::custom)?;

        let proof = bincode::serialize(&self.proof)
            .map_err(serde::ser::Error::custom)?;
        state.serialize_field("proof", &proof)?;

        state.end()
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use algebra::pasta::{
        fp::Fp,
        fq::Fq,
        pallas::Affine as Other,
        vesta::{Affine, VestaParameters},
    };
    use commitment_dlog::{commitment::ceil_log2, srs::SRS};

    use oracle::sponge_5_wires::{DefaultFqSponge, DefaultFrSponge};

    type SpongeQ = DefaultFqSponge<VestaParameters, crate::PlonkSpongeConstants>;
    type SpongeR = DefaultFrSponge<Fp, crate::PlonkSpongeConstants>;

    #[test]
    fn init_request_serde() {
        let srs = SRS::<Affine>::create(1 << 11);
        let other_srs = SRS::<Other>::create(1 << ceil_log2(crate::bba::MAX_COUNTERS));
        let big_srs = SRS::<Affine>::create(1 << 12);

        let (user_config, update_authority) =
            crate::init_participants_test(&srs, &other_srs, &big_srs);

        let init_secrets = crate::bba::init_secrets();
        let init_request = user_config.request_init::<SpongeQ, SpongeR>(init_secrets);

        // serialize
        let init_request_bytes = bincode::serialize(&init_request).unwrap();

        // deserialize
        //let init_request_decoded: crate::bba::InitRequest<algebra::short_weierstrass_jacobian::GroupAffine<algebra::pasta::pallas::PallasParameters>, algebra::short_weierstrass_jacobian::GroupAffine<algebra::pasta::vesta::VestaParameters>> = bincode::deserialize(&init_request_bytes[..]).unwrap();

        assert!(true);
    }
}
