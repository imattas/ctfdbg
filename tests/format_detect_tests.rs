use ctfdbg::target::format::FileFormat;
use ctfdbg::target::parser::detect_format;

#[test]
fn detect_pe_from_mz_signature() {
    let mut buf = vec![0u8; 0x100];
    buf[0] = b'M';
    buf[1] = b'Z';
    assert_eq!(detect_format(&buf), FileFormat::Pe);
}

#[test]
fn detect_elf_from_magic() {
    let mut buf = vec![0u8; 0x40];
    buf[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
    assert_eq!(detect_format(&buf), FileFormat::Elf);
}

#[test]
fn detect_unknown_for_random_bytes() {
    let buf = [1u8, 2, 3, 4, 5, 6, 7, 8];
    assert!(matches!(detect_format(&buf), FileFormat::Unknown | FileFormat::Raw));
}
