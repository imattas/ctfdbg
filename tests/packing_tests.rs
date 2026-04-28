use ctfdbg::pwn::packing::{p32, p64, u32_, u64_, Endian};

#[test]
fn p64_le_roundtrip() {
    let v = 0x4142434445464748u64;
    let bytes = p64(v, Endian::Little);
    assert_eq!(bytes, [0x48, 0x47, 0x46, 0x45, 0x44, 0x43, 0x42, 0x41]);
    assert_eq!(u64_(&bytes, Endian::Little).unwrap(), v);
}

#[test]
fn p64_be_roundtrip() {
    let v = 0xdeadbeefcafef00du64;
    let b = p64(v, Endian::Big);
    assert_eq!(u64_(&b, Endian::Big).unwrap(), v);
}

#[test]
fn p32_endianness() {
    assert_eq!(p32(0x11223344, Endian::Little), [0x44, 0x33, 0x22, 0x11]);
    assert_eq!(p32(0x11223344, Endian::Big), [0x11, 0x22, 0x33, 0x44]);
    assert_eq!(u32_(&[0x44, 0x33, 0x22, 0x11], Endian::Little).unwrap(), 0x11223344);
}
