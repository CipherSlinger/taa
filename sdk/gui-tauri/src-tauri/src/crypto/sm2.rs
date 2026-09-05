// SM2 elliptic curve cryptography — ported from Go crypto/sm2.go

use num_bigint::{BigInt, BigUint};
use num_traits::{One, Zero, ToPrimitive};
use rand::RngCore;
use std::sync::LazyLock;

use super::sm3::sm3_sum;

// ─── Curve Parameters ───────────────────────────────────────────────────────

pub struct SM2Curve {
    pub p: BigUint,
    pub n: BigUint,
    pub b: BigUint,
    pub gx: BigUint,
    pub gy: BigUint,
}

pub static SM2_CURVE: LazyLock<SM2Curve> = LazyLock::new(|| SM2Curve {
    p: BigUint::parse_bytes(b"FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF", 16).unwrap(),
    n: BigUint::parse_bytes(b"FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123", 16).unwrap(),
    b: BigUint::parse_bytes(b"28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93", 16).unwrap(),
    gx: BigUint::parse_bytes(b"32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7", 16).unwrap(),
    gy: BigUint::parse_bytes(b"BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0", 16).unwrap(),
});

const SM2_POINT_SIZE: usize = 65;
const SM3_SIZE: usize = 32;
pub const SM4_KEY_SIZE: usize = 16;
pub const SM2_WRAPPED_KEY_SIZE: usize = SM2_POINT_SIZE + SM3_SIZE + SM4_KEY_SIZE; // 113 bytes

// ─── Key Types ──────────────────────────────────────────────────────────────

#[derive(Clone, Debug)]
pub struct SM2PublicKey {
    pub x: BigUint,
    pub y: BigUint,
}

#[derive(Clone, Debug)]
pub struct SM2PrivateKey {
    pub public_key: SM2PublicKey,
    pub d: BigUint,
}

// ─── Key Generation ─────────────────────────────────────────────────────────

pub fn generate_sm2_key_pair() -> Result<SM2PrivateKey, String> {
    let d = random_sm2_scalar()?;
    let (x, y) = scalar_base_mult(&scalar_bytes(&d));
    Ok(SM2PrivateKey {
        public_key: SM2PublicKey { x, y },
        d,
    })
}

// ─── SM2 Encrypt ────────────────────────────────────────────────────────────

pub fn encrypt_sm2(pub_key: &SM2PublicKey, plaintext: &[u8]) -> Result<Vec<u8>, String> {
    if plaintext.is_empty() {
        return Err("SM2 明文不能为空".into());
    }
    validate_public_key(pub_key)?;

    loop {
        let k = random_sm2_scalar()?;
        let k_bytes = scalar_bytes(&k);
        let (c1x, c1y) = scalar_base_mult(&k_bytes);
        let (x2, y2) = scalar_mult(&pub_key.x, &pub_key.y, &k_bytes);

        let z = [coord_bytes(&x2), coord_bytes(&y2)].concat();
        let t = sm2_kdf(&z, plaintext.len());
        if t.iter().all(|&b| b == 0) {
            continue;
        }

        let c2 = xor_bytes(plaintext, &t);
        let mut c3_input = Vec::with_capacity(64 + plaintext.len());
        c3_input.extend_from_slice(&coord_bytes(&x2));
        c3_input.extend_from_slice(plaintext);
        c3_input.extend_from_slice(&coord_bytes(&y2));
        let c3 = sm3_sum(&c3_input);

        let mut ciphertext = Vec::with_capacity(SM2_POINT_SIZE + SM3_SIZE + c2.len());
        ciphertext.extend_from_slice(&marshal_point_unchecked(&c1x, &c1y));
        ciphertext.extend_from_slice(&c3);
        ciphertext.extend_from_slice(&c2);
        return Ok(ciphertext);
    }
}

// ─── SM2 Decrypt ────────────────────────────────────────────────────────────

pub fn decrypt_sm2(priv_key: &SM2PrivateKey, ciphertext: &[u8]) -> Result<Vec<u8>, String> {
    validate_private_key(priv_key)?;
    if ciphertext.len() <= SM2_POINT_SIZE + SM3_SIZE {
        return Err("SM2 密文长度不足".into());
    }

    let c1 = parse_point(&ciphertext[..SM2_POINT_SIZE])?;
    let c3 = &ciphertext[SM2_POINT_SIZE..SM2_POINT_SIZE + SM3_SIZE];
    let c2 = &ciphertext[SM2_POINT_SIZE + SM3_SIZE..];

    let d_bytes = scalar_bytes(&priv_key.d);
    let (x2, y2) = scalar_mult(&c1.x, &c1.y, &d_bytes);

    let z = [coord_bytes(&x2), coord_bytes(&y2)].concat();
    let t = sm2_kdf(&z, c2.len());
    if t.iter().all(|&b| b == 0) {
        return Err("SM2 KDF 输出无效".into());
    }
    let plaintext = xor_bytes(c2, &t);

    let mut c3_input = Vec::with_capacity(64 + plaintext.len());
    c3_input.extend_from_slice(&coord_bytes(&x2));
    c3_input.extend_from_slice(&plaintext);
    c3_input.extend_from_slice(&coord_bytes(&y2));
    let expected = sm3_sum(&c3_input);

    if c3 != expected.as_slice() {
        return Err("SM2 密文校验失败".into());
    }
    Ok(plaintext)
}

// ─── SM2 Sign/Verify ────────────────────────────────────────────────────────

pub fn sign_sm2(priv_key: &SM2PrivateKey, user_id: &[u8], msg: &[u8]) -> Result<(BigUint, BigUint), String> {
    validate_private_key(priv_key)?;
    let n = &SM2_CURVE.n;
    let e = sm2_message_digest(&priv_key.public_key, user_id, msg);
    let one = BigUint::one();
    let d_plus_one = (&priv_key.d + &one) % n;
    let inverse = mod_inverse(&d_plus_one, n).ok_or("SM2 私钥不可逆")?;

    loop {
        let k = random_sm2_scalar()?;
        let k_bytes = scalar_bytes(&k);
        let (x1, _) = scalar_base_mult(&k_bytes);
        let r = (&e + &x1) % n;
        if r.is_zero() || (&r + &k) == *n {
            continue;
        }
        let s = (&inverse * ((&k - (&r * &priv_key.d) % n + n) % n)) % n;
        if s.is_zero() {
            continue;
        }
        return Ok((r, s));
    }
}

pub fn verify_sm2(pub_key: &SM2PublicKey, user_id: &[u8], msg: &[u8], r: &BigUint, s: &BigUint) -> bool {
    if validate_public_key(pub_key).is_err() || r.is_zero() || s.is_zero() {
        return false;
    }
    let n = &SM2_CURVE.n;
    if r >= n || s >= n {
        return false;
    }
    let t = (r + s) % n;
    if t.is_zero() {
        return false;
    }

    let (sx, sy) = scalar_base_mult(&scalar_bytes(s));
    let (tx, ty) = scalar_mult(&pub_key.x, &pub_key.y, &scalar_bytes(&t));
    let (x1, _) = point_add(&sx, &sy, &tx, &ty);
    if x1.is_zero() && tx.is_zero() {
        return false;
    }
    let e = sm2_message_digest(pub_key, user_id, msg);
    let result = (&e + &x1) % n;
    result == *r
}

// ─── PEM Serialization ──────────────────────────────────────────────────────

// OIDs
const OID_EC_PUBLIC_KEY: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01]; // 1.2.840.10045.2.1
const OID_SM2_CURVE: &[u8] = &[0x2a, 0x81, 0x1c, 0xcf, 0x55, 0x01, 0x82, 0x2d]; // 1.2.156.10197.1.301

pub fn marshal_sm2_public_key_pem(pub_key: &SM2PublicKey) -> Result<Vec<u8>, String> {
    validate_public_key(pub_key)?;
    let point = marshal_point(pub_key)?;

    // AlgorithmIdentifier: SEQUENCE { OID ecPublicKey, OID sm2Curve }
    let algo = build_algorithm_identifier();
    // SubjectPublicKeyInfo: SEQUENCE { AlgorithmIdentifier, BIT STRING point }
    let spki = build_spki(&algo, &point);
    Ok(pem_encode("PUBLIC KEY", &spki))
}

pub fn marshal_sm2_private_key_pem(priv_key: &SM2PrivateKey) -> Result<Vec<u8>, String> {
    validate_private_key(priv_key)?;

    // ECPrivateKey: SEQUENCE { INTEGER 1, OCTET STRING d }
    let ec_der = build_ec_private_key(&priv_key.d);
    // PrivateKeyInfo: SEQUENCE { INTEGER 0, AlgorithmIdentifier, OCTET STRING ec_der }
    let pkcs8 = build_pkcs8(&ec_der);
    Ok(pem_encode("PRIVATE KEY", &pkcs8))
}

pub fn parse_sm2_public_key_pem(pem_data: &[u8]) -> Result<SM2PublicKey, String> {
    let (pem_type, der) = pem_decode(pem_data)?;
    if pem_type != "PUBLIC KEY" {
        return Err(format!("PEM 类型不是 SM2 公钥: {}", pem_type));
    }
    // Parse SubjectPublicKeyInfo
    let (data_start, _) = parse_sequence(&der, 0)?;
    let (_, algo_end) = parse_sequence(&der, data_start)?;
    if algo_end >= der.len() || der[algo_end] != 0x03 {
        return Err(format!("ASN.1: 期望 BIT STRING (pos={}, tag=0x{:02x})", algo_end, if algo_end < der.len() { der[algo_end] } else { 0xFF }));
    }
    let (point_bytes, _) = parse_bit_string(&der, algo_end)?;
    parse_point(point_bytes)
}

pub fn parse_sm2_private_key_pem(pem_data: &[u8]) -> Result<SM2PrivateKey, String> {
    let (pem_type, der) = pem_decode(pem_data)?;
    match pem_type.as_str() {
        "PRIVATE KEY" => parse_pkcs8_private_key(&der),
        "EC PRIVATE KEY" => parse_ec_private_key(&der),
        _ => Err(format!("PEM 类型不是 SM2 私钥: {}", pem_type)),
    }
}

// ─── Elliptic Curve Arithmetic ──────────────────────────────────────────────

fn scalar_base_mult(k: &[u8]) -> (BigUint, BigUint) {
    let curve = &*SM2_CURVE;
    scalar_mult(&curve.gx, &curve.gy, k)
}

fn scalar_mult(px: &BigUint, py: &BigUint, k: &[u8]) -> (BigUint, BigUint) {
    let p = &SM2_CURVE.p;
    let mut rx = BigUint::zero();
    let mut ry = BigUint::zero();
    let mut is_infinity = true;

    for byte in k {
        for bit in (0..8).rev() {
            if !is_infinity {
                let (nx, ny) = point_double(&rx, &ry, p);
                rx = nx;
                ry = ny;
            }
            if (byte >> bit) & 1 == 1 {
                if is_infinity {
                    rx = px.clone();
                    ry = py.clone();
                    is_infinity = false;
                } else {
                    let (nx, ny) = point_add(&rx, &ry, px, py);
                    rx = nx;
                    ry = ny;
                }
            }
        }
    }
    (rx, ry)
}

fn point_double(x: &BigUint, y: &BigUint, p: &BigUint) -> (BigUint, BigUint) {
    // a = p - 3 for SM2
    let a = p - BigUint::from(3u32);
    // lambda = (3*x^2 + a) / (2*y) mod p
    let x2 = (x * x) % p;
    let num = (&x2 * BigUint::from(3u32) + &a) % p;
    let den = (y * BigUint::from(2u32)) % p;
    let den_inv = mod_inverse(&den, p).unwrap_or_else(BigUint::zero);
    let lambda = (num * den_inv) % p;

    // x3 = lambda^2 - 2*x mod p
    let x3 = ((&lambda * &lambda) % p + p - (x * BigUint::from(2u32)) % p) % p;
    // y3 = lambda*(x - x3) - y mod p
    let y3 = ((&lambda * ((x + p - &x3) % p)) % p + p - y) % p;
    (x3, y3)
}

fn point_add(x1: &BigUint, y1: &BigUint, x2: &BigUint, y2: &BigUint) -> (BigUint, BigUint) {
    let p = &SM2_CURVE.p;
    if x1.is_zero() && y1.is_zero() {
        return (x2.clone(), y2.clone());
    }
    if x2.is_zero() && y2.is_zero() {
        return (x1.clone(), y1.clone());
    }
    if x1 == x2 && y1 == y2 {
        return point_double(x1, y1, p);
    }
    if x1 == x2 {
        return (BigUint::zero(), BigUint::zero());
    }

    // lambda = (y2 - y1) / (x2 - x1) mod p
    let num = (y2 + p - y1) % p;
    let den = (x2 + p - x1) % p;
    let den_inv = mod_inverse(&den, p).unwrap_or_else(BigUint::zero);
    let lambda = (num * den_inv) % p;

    // x3 = lambda^2 - x1 - x2 mod p
    let x3 = ((&lambda * &lambda) % p + p - x1 + p - x2) % p;
    // y3 = lambda*(x1 - x3) - y1 mod p
    let y3 = ((&lambda * ((x1 + p - &x3) % p)) % p + p - y1) % p;
    (x3, y3)
}

fn mod_inverse(a: &BigUint, m: &BigUint) -> Option<BigUint> {
    let a_s = BigInt::from(a.clone());
    let m_s = BigInt::from(m.clone());
    let mut old_r = a_s.clone();
    let mut r = m_s.clone();
    let mut old_s = BigInt::one();
    let mut s = BigInt::zero();

    while !r.is_zero() {
        let q = &old_r / &r;
        let temp_r = r.clone();
        r = &old_r - &q * &r;
        old_r = temp_r;

        let temp_s = s.clone();
        s = &old_s - &q * &s;
        old_s = temp_s;
    }

    if old_r != BigInt::one() {
        return None;
    }
    let result = ((old_s % &m_s) + &m_s) % &m_s;
    result.to_biguint()
}

// ─── Helpers ────────────────────────────────────────────────────────────────

fn random_sm2_scalar() -> Result<BigUint, String> {
    let n = &SM2_CURVE.n;
    let max = n - BigUint::one();
    let mut bytes = vec![0u8; 32];
    loop {
        rand::thread_rng().fill_bytes(&mut bytes);
        let d = BigUint::from_bytes_be(&bytes);
        if d >= BigUint::one() && d <= max {
            return Ok(d);
        }
    }
}

fn scalar_bytes(d: &BigUint) -> Vec<u8> {
    left_pad_32(&d.to_bytes_be())
}

fn coord_bytes(v: &BigUint) -> Vec<u8> {
    left_pad_32(&v.to_bytes_be())
}

fn left_pad_32(input: &[u8]) -> Vec<u8> {
    let mut out = vec![0u8; 32];
    if input.len() <= 32 {
        out[32 - input.len()..].copy_from_slice(input);
    }
    out
}

fn marshal_point(pub_key: &SM2PublicKey) -> Result<Vec<u8>, String> {
    validate_public_key(pub_key)?;
    Ok(marshal_point_unchecked(&pub_key.x, &pub_key.y))
}

fn marshal_point_unchecked(x: &BigUint, y: &BigUint) -> Vec<u8> {
    let mut point = vec![0u8; SM2_POINT_SIZE];
    point[0] = 4;
    let xb = x.to_bytes_be();
    let yb = y.to_bytes_be();
    point[1 + 32 - xb.len()..33].copy_from_slice(&xb);
    point[33 + 32 - yb.len()..].copy_from_slice(&yb);
    point
}

fn parse_point(point: &[u8]) -> Result<SM2PublicKey, String> {
    if point.len() != SM2_POINT_SIZE || point[0] != 4 {
        return Err("SM2 公钥点格式无效".into());
    }
    let x = BigUint::from_bytes_be(&point[1..33]);
    let y = BigUint::from_bytes_be(&point[33..]);
    let pub_key = SM2PublicKey { x, y };
    validate_public_key(&pub_key)?;
    Ok(pub_key)
}

fn validate_public_key(pub_key: &SM2PublicKey) -> Result<(), String> {
    if pub_key.x.is_zero() && pub_key.y.is_zero() {
        return Err("SM2 公钥为空".into());
    }
    if !is_on_curve(&pub_key.x, &pub_key.y) {
        return Err("SM2 公钥不在曲线上".into());
    }
    Ok(())
}

fn validate_private_key(priv_key: &SM2PrivateKey) -> Result<(), String> {
    if priv_key.d.is_zero() {
        return Err("SM2 私钥为空".into());
    }
    if priv_key.d >= SM2_CURVE.n {
        return Err("SM2 私钥标量无效".into());
    }
    validate_public_key(&priv_key.public_key)
}

fn is_on_curve(x: &BigUint, y: &BigUint) -> bool {
    let p = &SM2_CURVE.p;
    let b = &SM2_CURVE.b;
    // y^2 = x^3 + ax + b (mod p), where a = p - 3
    let y2 = (y * y) % p;
    let a = p - BigUint::from(3u32);
    let x3 = (x * x % p * x) % p;
    let rhs = (x3 + (&a * x) % p + b) % p;
    y2 == rhs
}

fn sm2_message_digest(pub_key: &SM2PublicKey, user_id: &[u8], msg: &[u8]) -> BigUint {
    let za = sm2_za(pub_key, user_id);
    let mut input = Vec::with_capacity(za.len() + msg.len());
    input.extend_from_slice(&za);
    input.extend_from_slice(msg);
    let digest = sm3_sum(&input);
    BigUint::from_bytes_be(&digest)
}

fn sm2_za(pub_key: &SM2PublicKey, user_id: &[u8]) -> Vec<u8> {
    let curve = &*SM2_CURVE;
    let a = &curve.p - BigUint::from(3u32);
    let entl = (user_id.len() * 8) as u16;
    let mut input = Vec::with_capacity(2 + user_id.len() + 32 * 6);
    input.push((entl >> 8) as u8);
    input.push(entl as u8);
    input.extend_from_slice(user_id);
    input.extend_from_slice(&coord_bytes(&a));
    input.extend_from_slice(&coord_bytes(&curve.b));
    input.extend_from_slice(&coord_bytes(&curve.gx));
    input.extend_from_slice(&coord_bytes(&curve.gy));
    input.extend_from_slice(&coord_bytes(&pub_key.x));
    input.extend_from_slice(&coord_bytes(&pub_key.y));
    sm3_sum(&input).to_vec()
}

fn sm2_kdf(z: &[u8], key_len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(key_len);
    let mut ct: u32 = 1;
    while out.len() < key_len {
        let mut input = Vec::with_capacity(z.len() + 4);
        input.extend_from_slice(z);
        input.extend_from_slice(&ct.to_be_bytes());
        let digest = sm3_sum(&input);
        out.extend_from_slice(&digest);
        ct += 1;
    }
    out.truncate(key_len);
    out
}

fn xor_bytes(a: &[u8], b: &[u8]) -> Vec<u8> {
    a.iter().zip(b.iter()).map(|(x, y)| x ^ y).collect()
}

// ─── ASN.1 DER Encoding/Decoding ────────────────────────────────────────────

fn build_algorithm_identifier() -> Vec<u8> {
    // SEQUENCE { OID ecPublicKey, OID sm2Curve }
    let mut inner = Vec::new();
    inner.extend_from_slice(&der_encode_oid(OID_EC_PUBLIC_KEY));
    inner.extend_from_slice(&der_encode_oid(OID_SM2_CURVE));
    der_encode_sequence(&inner)
}

fn build_spki(algo: &[u8], point: &[u8]) -> Vec<u8> {
    let mut inner = Vec::new();
    inner.extend_from_slice(algo);
    inner.extend_from_slice(&der_encode_bit_string(point));
    der_encode_sequence(&inner)
}

fn build_ec_private_key(d: &BigUint) -> Vec<u8> {
    let mut inner = Vec::new();
    inner.extend_from_slice(&der_encode_integer(&BigUint::from(1u32)));
    inner.extend_from_slice(&der_encode_octet_string(&scalar_bytes(d)));
    der_encode_sequence(&inner)
}

fn build_pkcs8(ec_der: &[u8]) -> Vec<u8> {
    let algo = build_algorithm_identifier();
    let mut inner = Vec::new();
    inner.extend_from_slice(&der_encode_integer(&BigUint::zero()));
    inner.extend_from_slice(&algo);
    inner.extend_from_slice(&der_encode_octet_string(ec_der));
    der_encode_sequence(&inner)
}

fn der_encode_oid(oid: &[u8]) -> Vec<u8> {
    let mut out = vec![0x06, oid.len() as u8];
    out.extend_from_slice(oid);
    out
}

fn der_encode_integer(val: &BigUint) -> Vec<u8> {
    let mut bytes = val.to_bytes_be();
    if bytes.is_empty() || bytes[0] == 0 {
        bytes = vec![0];
    }
    if bytes[0] & 0x80 != 0 {
        bytes.insert(0, 0);
    }
    let mut out = vec![0x02, bytes.len() as u8];
    out.extend_from_slice(&bytes);
    out
}

fn der_encode_bit_string(data: &[u8]) -> Vec<u8> {
    let len = data.len() + 1; // +1 for unused bits byte
    let mut out = vec![0x03];
    out.extend_from_slice(&der_encode_length(len));
    out.push(0x00); // unused bits
    out.extend_from_slice(data);
    out
}

fn der_encode_octet_string(data: &[u8]) -> Vec<u8> {
    let mut out = vec![0x04];
    out.extend_from_slice(&der_encode_length(data.len()));
    out.extend_from_slice(data);
    out
}

fn der_encode_sequence(data: &[u8]) -> Vec<u8> {
    let mut out = vec![0x30];
    out.extend_from_slice(&der_encode_length(data.len()));
    out.extend_from_slice(data);
    out
}

fn der_encode_length(len: usize) -> Vec<u8> {
    if len < 128 {
        vec![len as u8]
    } else if len < 256 {
        vec![0x81, len as u8]
    } else {
        vec![0x82, (len >> 8) as u8, len as u8]
    }
}

// ─── ASN.1 DER Decoding ─────────────────────────────────────────────────────

fn parse_sequence(data: &[u8], offset: usize) -> Result<(usize, usize), String> {
    if offset >= data.len() || data[offset] != 0x30 {
        return Err("ASN.1: 期望 SEQUENCE".into());
    }
    let (len, data_start) = parse_der_length(data, offset + 1)?;
    Ok((data_start, data_start + len))
}

fn parse_der_length(data: &[u8], offset: usize) -> Result<(usize, usize), String> {
    if offset >= data.len() {
        return Err("ASN.1: 长度越界".into());
    }
    let first = data[offset];
    if first < 128 {
        Ok((first as usize, offset + 1))
    } else if first == 0x81 {
        if offset + 1 >= data.len() {
            return Err("ASN.1: 长度越界".into());
        }
        Ok((data[offset + 1] as usize, offset + 2))
    } else if first == 0x82 {
        if offset + 2 >= data.len() {
            return Err("ASN.1: 长度越界".into());
        }
        let len = ((data[offset + 1] as usize) << 8) | (data[offset + 2] as usize);
        Ok((len, offset + 3))
    } else {
        Err("ASN.1: 不支持的长度编码".into())
    }
}

fn parse_bit_string(data: &[u8], offset: usize) -> Result<(&[u8], usize), String> {
    if offset >= data.len() || data[offset] != 0x03 {
        return Err("ASN.1: 期望 BIT STRING".into());
    }
    let (len, end) = parse_der_length(data, offset + 1)?;
    if len < 1 || data[end] != 0x00 {
        return Err("ASN.1: BIT STRING 格式无效".into());
    }
    Ok((&data[end + 1..end + len], end + len))
}

fn parse_ec_private_key(der: &[u8]) -> Result<SM2PrivateKey, String> {
    let (data_start, _) = parse_sequence(der, 0)?;
    let mut pos = data_start;
    // INTEGER version (should be 1): tag(1) + length(1) + value(1) = 3 bytes
    if pos >= der.len() || der[pos] != 0x02 || pos + 2 >= der.len() || der[pos + 1] != 0x01 {
        return Err(format!("ASN.1: EC 私钥版本无效 (pos={})", pos));
    }
    pos += 3; // skip tag + length + value
    // OCTET STRING privateKey
    if pos >= der.len() {
        return Err(format!("ASN.1: 越界 (pos={})", pos));
    }
    if der[pos] != 0x04 {
        return Err(format!("ASN.1: 期望 OCTET STRING (pos={}, tag=0x{:02x})", pos, der[pos]));
    }
    let (len, octet_data_start) = parse_der_length(der, pos + 1)?;
    let d_bytes = &der[octet_data_start..octet_data_start + len];
    let d = BigUint::from_bytes_be(d_bytes);
    if d.is_zero() || d >= SM2_CURVE.n {
        return Err("SM2 私钥标量无效".into());
    }
    let (x, y) = scalar_base_mult(&scalar_bytes(&d));
    Ok(SM2PrivateKey {
        public_key: SM2PublicKey { x, y },
        d,
    })
}

fn parse_pkcs8_private_key(der: &[u8]) -> Result<SM2PrivateKey, String> {
    let (data_start, seq_end) = parse_sequence(der, 0)?;
    let mut pos = data_start;
    // INTEGER version (should be 0)
    if der[pos] != 0x02 || der[pos + 1] != 0x01 || der[pos + 2] != 0x00 {
        return Err(format!("ASN.1: PKCS#8 版本无效 (pos={})", pos));
    }
    pos += 3;
    // SEQUENCE AlgorithmIdentifier
    let (algo_data_start, algo_end) = parse_sequence(der, pos)?;
    pos = algo_end;
    // OCTET STRING ecPrivateKey
    if pos >= der.len() {
        return Err(format!("ASN.1: 越界 (pos={}, len={})", pos, der.len()));
    }
    if der[pos] != 0x04 {
        return Err(format!("ASN.1: 期望 OCTET STRING (pos={}, tag=0x{:02x}, algo_end={})", pos, der[pos], algo_end));
    }
    let (len, octet_data_start) = parse_der_length(der, pos + 1)?;
    parse_ec_private_key(&der[octet_data_start..octet_data_start + len])
}

fn pem_decode(data: &[u8]) -> Result<(String, Vec<u8>), String> {
    let text = std::str::from_utf8(data).map_err(|_| "PEM 数据不是 UTF-8")?;
    let begin_marker = "-----BEGIN ";
    let end_marker = "-----END ";
    let begin_pos = text.find(begin_marker).ok_or("找不到 PEM BEGIN")?;
    let type_start = begin_pos + begin_marker.len();
    let type_end = text[type_start..].find("-----").ok_or("PEM 格式无效")? + type_start;
    let pem_type = text[type_start..type_end].trim_end_matches('-').to_string();
    let data_start = text.find("-----\n").or_else(|| text.find("-----\r\n")).ok_or("PEM 格式无效")? + 6;
    let end_pos = text.find(end_marker).ok_or("找不到 PEM END")?;
    let b64_data: String = text[data_start..end_pos].chars().filter(|c| !c.is_whitespace()).collect();
    let decoded = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &b64_data)
        .map_err(|e| format!("Base64 解码失败: {}", e))?;
    Ok((pem_type, decoded))
}

fn pem_encode(pem_type: &str, data: &[u8]) -> Vec<u8> {
    use base64::Engine;
    let b64 = base64::engine::general_purpose::STANDARD.encode(data);
    let mut out = format!("-----BEGIN {}-----\n", pem_type);
    for chunk in b64.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(chunk).unwrap());
        out.push('\n');
    }
    out.push_str(&format!("-----END {}-----\n", pem_type));
    out.into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_roundtrip() {
        let priv_key = generate_sm2_key_pair().unwrap();
        let pem = marshal_sm2_private_key_pem(&priv_key).unwrap();
        eprintln!("Generated PEM:\n{}", String::from_utf8_lossy(&pem));

        match parse_sm2_private_key_pem(&pem) {
            Ok(parsed) => {
                assert_eq!(priv_key.d, parsed.d);
                eprintln!("✓ Key roundtrip successful");
            }
            Err(e) => {
                eprintln!("✗ Parse failed: {}", e);
                panic!("Failed to parse generated key: {}", e);
            }
        }
    }
}
