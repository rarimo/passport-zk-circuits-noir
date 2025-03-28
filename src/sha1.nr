
fn u32_to_u8(input: [u32; 5]) -> [u8; 20] {
    let mut output = [0; 20];

    for i in 0..5 {
        output[i * 4]     = (input[i] >> 24) as u8; // Most significant byte (MSB)
        output[i * 4 + 1] = (input[i] >> 16) as u8;
        output[i * 4 + 2] = (input[i] >> 8) as u8;
        output[i * 4 + 3] = (input[i]) as u8;       // Least significant byte (LSB)
    }

    output
}

fn u8_to_u32(input: [u8; 64]) -> [u32; 16] {
    let mut output = [0; 16];

    for i in 0..16 {
        output[i] = (input[i * 4] as u32) << 24 |
                    (input[i * 4 + 1] as u32) << 16 |
                    (input[i * 4 + 2] as u32) << 8 |
                    (input[i * 4 + 3] as u32);
    }

    output
}

fn init() -> ([u32; 5]){
    [
        0x67452301,
        0xefcdab89,
        0x98badcfe,
        0x10325476,
        0xc3d2e1f0
    ]
}

fn rotate_left(a: u32, b: u8) -> u32 {
    ((a << b) & 0xFFFFFFFF) | (a >> (32 - b))
}

fn process_chunk(state: [u32; 5], chunk: [u32; 16]) -> [u32; 5]{
    let mut w = [0; 80];
    for i in 0..16{
        w[i] = chunk[i];
    }
    for i in 16..80{
        w[i] = rotate_left(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
    }
    
    let mut a: u32 = state[0];
    let mut b: u32 = state[1];
    let mut c: u32 = state[2];
    let mut d: u32 = state[3];
    let mut e: u32 = state[4];

    for i in 0..80{
        let mut f = 0;
        let mut k = 0;

        if i < 20{
            f = (b & c) | ((0xFFFFFFFF - b) & d);
            k = 0x5A827999;
        } else {
            if i < 40 {
                f = b ^ c ^ d;
                k = 0x6ED9EBA1;
            } else {
                if i < 60{
                    f = (b & c) | (b & d) | (c & d);
                    k = 0x8F1BBCDC;
                } else {
                    f = b ^ c ^ d;
                    k = 0xCA62C1D6;
                }
            }
        }
        let temp: u32 = ((rotate_left(a, 5) as u64 + f as u64 + e as u64+ w[i] as u64 + k as u64) & 0xFFFFFFFF) as u32;

        e = d;
        d = c;
        c = rotate_left(b, 30);
        b = a;
        a = temp;
    }

    [
        ((state[0] as u64 + a as u64) & 0xFFFFFFFF) as u32,
        ((state[1] as u64 + b as u64) & 0xFFFFFFFF) as u32,
        ((state[2] as u64 + c as u64) & 0xFFFFFFFF) as u32,
        ((state[3] as u64 + d as u64) & 0xFFFFFFFF) as u32,
        ((state[4] as u64 + e as u64) & 0xFFFFFFFF) as u32,
    ]
}


pub fn digest<let N: u32>(msg: [u8; N]) -> [u8; 20] {
    let mut msg_block: [u8; 64] = [0; 64];
    let mut i: u64 = 0; // Message byte pointer
    let mut state = init();
    for k in 0..msg.len() {
        // Populate msg_block
        msg_block[i] = msg[k];
        i = i + 1;
        if i == 64 {
            // Enough to hash block
            state = process_chunk(state, u8_to_u32(msg_block));
            i = 0;
        }
    }
    msg_block[i] = 1 << 7;
    i += 1;

    if i >= 49 {
        // Not enough bits (128) to store length. Fill up with zeros.
        if i < 64 {
            for _i in 49..64 {
                if i <= 63 {
                    msg_block[i] = 0;
                    i += 1;
                }
            }
        }
        state = process_chunk(state, u8_to_u32(msg_block));

        i = 0;
    }

    let len = 8 * msg.len();
    let len_bytes: [u8; 16] = (len as Field).to_le_bytes();
    for _i in 0..64 {
        // In any case, fill blocks up with zeros until the last 128 (i.e. until i = 112).
        if i < 48 {
            msg_block[i] = 0;
            i += 1;
        } else if i < 64 {
            for j in 0..16 {
                msg_block[63 - j] = len_bytes[j];
            }
            i += 16; // Done.
        }
    }

    state = process_chunk(state, u8_to_u32(msg_block));

    u32_to_u8(state)
}   

#[test]
fn test_sha1_2_chunks() {
    let res = digest::<66>([0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]);
    assert(res == [112, 126, 252, 49, 78, 197, 54, 171, 237, 83, 92, 219, 27, 36, 20, 171, 164, 113, 53, 119]);
}

#[test]
fn test_sha1_1_chunk() {
    let res = digest::<2>([0,0]);
    assert(res == [20, 137, 249, 35, 196, 220, 167, 41, 23, 139, 62, 50, 51, 69, 133, 80, 216, 221, 223, 41]);
}