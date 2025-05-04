use std::hash::poseidon::PoseidonHasher;
use super::utils::{switcher};

fn smt_hash1(
    key: Field,
    value: Field) -> Field{
    let mut hasher = PoseidonHasher::default();
    hasher.write(key);
    hasher.write(value);
    hasher.write(1);
    hasher.finish()
}


fn smt_hash2(
    l: Field,
    r: Field) -> Field{
    let mut hasher = PoseidonHasher::default();
    hasher.write(l);
    hasher.write(r);
    hasher.finish()
}

fn smt_level_ins<let N_LEVELS: u32>(
    siblings: [Field; N_LEVELS]) -> [Field; N_LEVELS]{
    let mut done: [Field; (N_LEVELS - 1)] = [0; N_LEVELS - 1];
    assert(siblings[N_LEVELS - 1].eq(0) as Field == 1, "SMT inner verification failure");
    let mut out = [0; N_LEVELS];

    out[N_LEVELS - 1] = 1 - siblings[N_LEVELS - 2].eq(0) as Field;
    done[N_LEVELS - 2] = out[N_LEVELS - 1];

    for i in 0..N_LEVELS - 2{
        out[N_LEVELS - 2 - i] = 
            (1 - done[N_LEVELS - 2 - i]) * 
            (1 - siblings[N_LEVELS - 3 - i].eq(0) as Field);
        done[N_LEVELS - 3 - i] = 
            out[N_LEVELS - 2 - i] + done[N_LEVELS - 2 - i];
    }
    out[0] = 1 - done[0];
    out
}

fn smt_verifier_sm(lev_ins: Field, prev_top: Field) -> (Field, Field){
    let st_inew = prev_top * lev_ins;
    (st_inew, prev_top - st_inew)
}

fn smt_verifier_level(
    st_top: Field,
    st_inew: Field,
    sibling: Field,
    new_1_leaf: Field,
    lrbit: u1,
    child: Field
) -> Field{

    let switcher = switcher(child, sibling, lrbit);
    let proof_hash = smt_hash2(switcher.0, switcher.1);
    let from_proof= proof_hash * st_top;

    from_proof + new_1_leaf * st_inew
}

pub fn smt_verifier<let N_LEVELS: u32>(
    root: Field,
    leaf: Field,
    key: Field,
    siblings: [Field; N_LEVELS]) -> u1{
    
    let hash1_new = smt_hash1(key, leaf);

    let key_bits: [u1; 254] = key.to_le_bits();
    
    let smt_lev_ins_out = smt_level_ins::<N_LEVELS>(siblings);

    let mut sm_outs: [(Field, Field); N_LEVELS] = [(0,0); N_LEVELS];

    sm_outs[0] = smt_verifier_sm(smt_lev_ins_out[0], 1);

    for i in 1..N_LEVELS{
        sm_outs[i] = smt_verifier_sm(smt_lev_ins_out[i], sm_outs[i - 1].1);
    }

    let mut levels: [Field; N_LEVELS] = [0; N_LEVELS];

    levels[N_LEVELS - 1] = smt_verifier_level(sm_outs[N_LEVELS - 1].1, sm_outs[N_LEVELS - 1].0, siblings[N_LEVELS - 1], hash1_new, key_bits[N_LEVELS - 1], 0);
    for i in 1..N_LEVELS{
        levels[N_LEVELS - 1 - i] = smt_verifier_level(sm_outs[N_LEVELS - 1 - i].1, sm_outs[N_LEVELS - 1 - i].0, siblings[N_LEVELS - 1 - i], hash1_new, key_bits[N_LEVELS - 1 - i], levels[N_LEVELS - i]);
    }

    (levels[0] == root) as u1
}

#[test]
fn test(){
    print(smt_verifier::<80>(
        11035164876722493867956800399324037851238296649576168185861461383200281731661,
        1914080321768737626845532766495249233577737596115572855738207100669611480269,
        1914080321768737626845532766495249233577737596115572855738207100669611480269,
        [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]
        ));
}