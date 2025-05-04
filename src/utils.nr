
pub fn is_zero(x: Field) -> Field {
    let inv = if x != 0 { 1 / x } else { 0 };
    let out = 1 - (x * inv);
    
    assert(x * out == 0, "Is zero assert failed");

    out
}

pub fn switcher(l: Field, r: Field, bit: u1) -> (Field, Field){
    let aux = (r - l) * (bit as Field);
    (aux + l, -aux + r)
}
