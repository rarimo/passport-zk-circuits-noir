pub fn switcher(l: Field, r: Field, bit: u1) -> (Field, Field){
    let aux = (r - l) * (bit as Field);
    (aux + l, -aux + r)
}
