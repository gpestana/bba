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

use oracle::{
    poseidon_5_wires::*,
    sponge_5_wires::{DefaultFqSponge, DefaultFrSponge},
};

pub type GroupAffinePallas = algebra::short_weierstrass_jacobian::GroupAffine<PallasParameters>;
pub type GroupAffineVesta = algebra::short_weierstrass_jacobian::GroupAffine<VestaParameters>;

type SpongeQ = DefaultFqSponge<VestaParameters, PlonkSpongeConstants>;
type SpongeR = DefaultFrSponge<Fp, PlonkSpongeConstants>;

type PSpongeQ = DefaultFqSponge<PallasParameters, PlonkSpongeConstants>;
type PSpongeR = DefaultFrSponge<Fq, PlonkSpongeConstants>;

/// Initializes issuer
pub fn init_issuer<'a>(
    srs: &'a commitment_dlog::srs::SRS<GroupAffineVesta>,
    big_srs: &'a commitment_dlog::srs::SRS<GroupAffineVesta>,
) -> bba::UpdateAuthority<'a, GroupAffinePallas, GroupAffineVesta> {
    // TODO: create factory for signer?
    let (_endo_q, endo_r) = endos::<Other>();
    let signer = schnorr::Signer::<Other> {
        sponge: oracle::pasta::fp5::params(),
        endo: endo_r,
    };

    let other_srs = SRS::<Other>::create(1 << ceil_log2(bba::MAX_COUNTERS));
    let group_map = <Affine as CommitmentCurve>::Map::setup();
    let fq_poseidon = oracle::pasta::fq5::params();

    let proof_system_constants = proof_system::fp_constants();

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

    let init_pk = proof_system::generate_proving_key::<proof_system::FpInner, _>(
        &big_srs,
        &proof_system_constants,
        &fq_poseidon,
        2,
        |sys, p| bba_init_proof::circuit::<_, Other, _>(&init_params, &None, sys, p),
    );
    let init_vk = init_pk.verifier_index();

    let h = other_srs.h.to_coordinates().unwrap();
    let update_params = bba_update_proof::Params {
        brave_pubkey: brave_pubkey.to_coordinates().unwrap(),
        h,
    };
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
    authority: bba::UpdateAuthority<'a, GroupAffinePallas, GroupAffineVesta>,
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
