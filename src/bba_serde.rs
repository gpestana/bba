#[cfg(test)]
mod test {
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

        assert!(true);
    }
}
