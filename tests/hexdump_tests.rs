use ctfdbg::pwn::hexdump::hexdump;

#[test]
fn hexdump_includes_address_and_ascii() {
    let bytes = b"Hello, world!\x00\x01\x02";
    let s = hexdump(bytes, 0x1000);
    assert!(s.contains("0000000000001000"), "missing address: {s}");
    assert!(s.contains("Hello"), "missing ascii: {s}");
    // Check that non-printable bytes render as '.'
    assert!(s.contains(".."), "non-printables should be dots: {s}");
}

#[test]
fn hexdump_handles_empty_input() {
    assert_eq!(hexdump(b"", 0).trim(), "");
}
