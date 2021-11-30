pub mod bba;
pub mod bba_init_proof;
pub mod bba_open_proof;
pub mod bba_update_proof;
pub mod endo;
pub mod fft;
pub mod proof_system;
pub mod random_oracle;
pub mod schnorr;
pub mod util;

use mina_curves::pasta::{
    fp::Fp,
    fq::Fq,
    pallas::{Affine as Other, PallasParameters},
    vesta::{Affine, VestaParameters},
};

use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_ff::UniformRand;

use array_init::array_init;
use commitment_dlog::{
    commitment::{ceil_log2, CommitmentCurve, PolyComm},
    srs::{endos, SRS},
};

use groupmap::GroupMap;

use oracle::{
    poseidon::*,
    sponge::{DefaultFqSponge, DefaultFrSponge},
};

type SpongeQ = DefaultFqSponge<VestaParameters, PlonkSpongeConstants5W>;
type SpongeR = DefaultFrSponge<Fp, PlonkSpongeConstants5W>;

type PSpongeQ = DefaultFqSponge<PallasParameters, PlonkSpongeConstants5W>;
type PSpongeR = DefaultFrSponge<Fq, PlonkSpongeConstants5W>;

/// Initializes issuer
pub fn init_issuer<'a>(
    srs: &'a commitment_dlog::srs::SRS<
        ark_ec::short_weierstrass_jacobian::GroupAffine<mina_curves::pasta::vesta::VestaParameters>,
    >,
    big_srs: &'a commitment_dlog::srs::SRS<
        ark_ec::short_weierstrass_jacobian::GroupAffine<mina_curves::pasta::vesta::VestaParameters>,
    >,
) -> bba::UpdateAuthority<
    'a,
    ark_ec::short_weierstrass_jacobian::GroupAffine<mina_curves::pasta::pallas::PallasParameters>,
    ark_ec::short_weierstrass_jacobian::GroupAffine<mina_curves::pasta::vesta::VestaParameters>,
> {
    // TODO: create factory for signer?
    let (_endo_q, endo_r) = endos::<Other>();
    let signer = schnorr::Signer::<Other> {
        sponge: oracle::pasta::fp5::params(),
        endo: endo_r,
    };

    let other_srs = SRS::<Other>::create(1 << ceil_log2(bba::MAX_COUNTERS));
    let group_map = <Affine as CommitmentCurve>::Map::setup();
    let g_group_map = <Other as CommitmentCurve>::Map::setup();
    let fq_poseidon = oracle::pasta::fq5::params();

    let proof_system_constants = proof_system::fp_constants();
    let fq_proof_system_constants = proof_system::fq_constants();

    // TODO: refactor / as input?
    let brave_sk = <Other as AffineCurve>::ScalarField::rand(&mut rand_core::OsRng);
    let brave_pubkey = Other::prime_subgroup_generator()
        .mul(brave_sk)
        .into_affine();

    let bba = bba::Params::new(&other_srs, endo_r);
    let init_params = bba_init_proof::Params {
        lagrange_commitments: array_init(|i| bba.lagrange_commitments[i]),
        h: other_srs.h,
    };
    let h = other_srs.h.to_coordinates().unwrap();
    let update_params = bba_update_proof::Params {
        brave_pubkey: brave_pubkey.to_coordinates().unwrap(),
        h,
    };

    let group_map = <Affine as CommitmentCurve>::Map::setup();

    let init_params = bba_init_proof::Params {
        lagrange_commitments: array_init(|i| bba.lagrange_commitments[i]),
        h: other_srs.h,
    };

    let init_pk = proof_system::generate_proving_key::<proof_system::FpInner, _>(
        &big_srs,
        &proof_system_constants,
        &fq_poseidon,
        2,
        |sys, p| bba_init_proof::circuit::<_, Other, _>(&init_params, &None, sys, p),
    );
    let init_vk = init_pk.verifier_index();

    let update_pk = proof_system::generate_proving_key::<proof_system::FpInner, _>(
        &srs,
        &proof_system_constants,
        &fq_poseidon,
        2,
        |sys, p| {
            bba_update_proof::circuit::<_, Other, _>(
                &proof_system_constants,
                &update_params,
                &None,
                sys,
                p,
            )
        },
    );
    let update_vk = update_pk.verifier_index();

    let other_lgr_comms: Vec<PolyComm<Affine>> = fft::lagrange_commitments(&srs)
        .iter()
        .map(|g| PolyComm {
            unshifted: vec![*g],
            shifted: None,
        })
        .collect();

    let big_other_lgr_comms: Vec<PolyComm<Affine>> = fft::lagrange_commitments(&big_srs)
        .iter()
        .map(|g| PolyComm {
            unshifted: vec![*g],
            shifted: None,
        })
        .collect();

    bba::UpdateAuthority {
        signing_key: brave_sk,
        signer: signer.clone(),
        group_map: group_map.clone(),
        other_lgr_comms,
        big_other_lgr_comms,
        lgr_comms: bba.lagrange_commitments.clone(),
        init_vk,
        update_vk,
    }
}

fn init_sign<'a>(
    authority: bba::UpdateAuthority<
        'a,
        ark_ec::short_weierstrass_jacobian::GroupAffine<
            mina_curves::pasta::pallas::PallasParameters,
        >,
        ark_ec::short_weierstrass_jacobian::GroupAffine<mina_curves::pasta::vesta::VestaParameters>,
    >,
    init_request: Vec<u8>,
    acc: Vec<u8>,
) -> Vec<u8> {
    // deserialize init_request
    // deserialize acc

    //let init_signature = authority.batch_init::<SpongeQ, SpongeR>(
    //    vec![init_request, acc]
    //).unwrap()[0];

    vec![]
}

/// Returns version of the bba_scheme
pub fn version() -> String {
    "bba_lib:0.1".to_string()
}
