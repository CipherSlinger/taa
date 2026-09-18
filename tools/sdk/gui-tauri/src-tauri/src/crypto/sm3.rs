// SM3 cryptographic hash algorithm — ported from Go crypto/sm3.go

pub const SM3_SIZE: usize = 32;
const SM3_BLOCK_SIZE: usize = 64;

const SM3_IV: [u32; 8] = [
    0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600,
    0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e,
];

pub fn sm3_sum(data: &[u8]) -> [u8; SM3_SIZE] {
    let mut state = SM3_IV;
    let padded = sm3_pad(data);
    for chunk in padded.chunks_exact(SM3_BLOCK_SIZE) {
        let mut block = [0u8; SM3_BLOCK_SIZE];
        block.copy_from_slice(chunk);
        sm3_compress(&mut state, &block);
    }
    let mut out = [0u8; SM3_SIZE];
    for (i, &v) in state.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&v.to_be_bytes());
    }
    out
}

pub fn hmac_sm3(key: &[u8], data: &[u8]) -> [u8; SM3_SIZE] {
    let key = if key.len() > SM3_BLOCK_SIZE {
        let h = sm3_sum(key);
        h.to_vec()
    } else {
        key.to_vec()
    };
    let mut padded_key = vec![0u8; SM3_BLOCK_SIZE];
    padded_key[..key.len()].copy_from_slice(&key);

    let ipad: Vec<u8> = padded_key.iter().map(|&b| b ^ 0x36).collect();
    let opad: Vec<u8> = padded_key.iter().map(|&b| b ^ 0x5c).collect();

    let mut inner_input = Vec::with_capacity(SM3_BLOCK_SIZE + data.len());
    inner_input.extend_from_slice(&ipad);
    inner_input.extend_from_slice(data);
    let inner = sm3_sum(&inner_input);

    let mut outer_input = Vec::with_capacity(SM3_BLOCK_SIZE + SM3_SIZE);
    outer_input.extend_from_slice(&opad);
    outer_input.extend_from_slice(&inner);
    sm3_sum(&outer_input)
}

fn sm3_pad(data: &[u8]) -> Vec<u8> {
    let bit_len = (data.len() as u64) * 8;
    let mut padded_len = data.len() + 1 + 8;
    let rem = padded_len % SM3_BLOCK_SIZE;
    if rem != 0 {
        padded_len += SM3_BLOCK_SIZE - rem;
    }
    let mut padded = vec![0u8; padded_len];
    padded[..data.len()].copy_from_slice(data);
    padded[data.len()] = 0x80;
    padded[padded_len - 8..].copy_from_slice(&bit_len.to_be_bytes());
    padded
}

fn sm3_compress(state: &mut [u32; 8], block: &[u8; SM3_BLOCK_SIZE]) {
    let mut w = [0u32; 68];
    let mut w1 = [0u32; 64];
    for i in 0..16 {
        w[i] = u32::from_be_bytes([block[i * 4], block[i * 4 + 1], block[i * 4 + 2], block[i * 4 + 3]]);
    }
    for i in 16..68 {
        w[i] = sm3_p1(w[i - 16] ^ w[i - 9] ^ w[i - 3].rotate_left(15))
            ^ w[i - 13].rotate_left(7)
            ^ w[i - 6];
    }
    for i in 0..64 {
        w1[i] = w[i] ^ w[i + 4];
    }

    let (mut a, mut b, mut c, mut d) = (state[0], state[1], state[2], state[3]);
    let (mut e, mut f, mut g, mut h) = (state[4], state[5], state[6], state[7]);
    for i in 0..64 {
        let ss1 = (a.rotate_left(12).wrapping_add(e).wrapping_add(sm3_t(i).rotate_left(i as u32)))
            .rotate_left(7);
        let ss2 = ss1 ^ a.rotate_left(12);
        let tt1 = sm3_ff(i, a, b, c).wrapping_add(d).wrapping_add(ss2).wrapping_add(w1[i]);
        let tt2 = sm3_gg(i, e, f, g).wrapping_add(h).wrapping_add(ss1).wrapping_add(w[i]);
        d = c;
        c = b.rotate_left(9);
        b = a;
        a = tt1;
        h = g;
        g = f.rotate_left(19);
        f = e;
        e = sm3_p0(tt2);
    }

    state[0] ^= a;
    state[1] ^= b;
    state[2] ^= c;
    state[3] ^= d;
    state[4] ^= e;
    state[5] ^= f;
    state[6] ^= g;
    state[7] ^= h;
}

fn sm3_t(i: usize) -> u32 {
    if i < 16 { 0x79cc4519 } else { 0x7a879d8a }
}

fn sm3_ff(i: usize, x: u32, y: u32, z: u32) -> u32 {
    if i < 16 { x ^ y ^ z } else { (x & y) | (x & z) | (y & z) }
}

fn sm3_gg(i: usize, x: u32, y: u32, z: u32) -> u32 {
    if i < 16 { x ^ y ^ z } else { (x & y) | ((!x) & z) }
}

fn sm3_p0(x: u32) -> u32 {
    x ^ x.rotate_left(9) ^ x.rotate_left(17)
}

fn sm3_p1(x: u32) -> u32 {
    x ^ x.rotate_left(15) ^ x.rotate_left(23)
}
