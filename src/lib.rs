pub mod bba;
mod bba_init_proof;
mod bba_open_proof;
mod bba_update_proof;
mod endo;
mod fft;
mod proof_system;
mod random_oracle;
mod schnorr;
mod util;

use serde::Serialize;

use algebra::{
    pasta::{
        fp::Fp,
        fq::Fq,
        pallas::{Affine as Other, PallasParameters},
        vesta::{Affine, VestaParameters},
    },
    AffineCurve, ProjectiveCurve, UniformRand,
};

use array_init::array_init;
use commitment_dlog::{
    commitment::{ceil_log2, CommitmentCurve, PolyComm},
    srs::{endos, SRS},
};

use groupmap::GroupMap;

/// Initializes issuer
pub fn init_issuer<'a>(
    srs: &'a commitment_dlog::srs::SRS<
        algebra::short_weierstrass_jacobian::GroupAffine<algebra::pasta::vesta::VestaParameters>,
    >,
    big_srs: &'a commitment_dlog::srs::SRS<
        algebra::short_weierstrass_jacobian::GroupAffine<algebra::pasta::vesta::VestaParameters>,
    >,
) -> bba::UpdateAuthority<
    'a,
    algebra::short_weierstrass_jacobian::GroupAffine<algebra::pasta::pallas::PallasParameters>,
    algebra::short_weierstrass_jacobian::GroupAffine<algebra::pasta::vesta::VestaParameters>,
> {
    // TODO: create factory for signer?
    let (_endo_q, endo_r) = endos::<Other>();
    let signer = schnorr::Signer::<Other> {
        sponge: oracle::pasta::fp5::params(),
        endo: endo_r,
    };

    // TODO:refactor init public key to factory? (i.e. trusted setup/ proof system)
    //let () = SRS::<Affine>::create(1 << 11);

    //let srs = SRS::<Affine>::create(1 << 11);
    //let big_srs = SRS::<Affine>::create(1 << 12);

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

    // TODO what?
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

/// Returns version of the bba_scheme
pub fn version() -> String {
    "bba_lib:0.1".to_string()
}
