use ctfdbg::pwn::cyclic::{cyclic, cyclic_find};

#[test]
fn cyclic_default_prefix_is_deterministic_de_bruijn() {
    // First several symbols of a de Bruijn sequence over the default alphabet
    // (A..Z a..z 0..9) with subsequence length 4 are AAAAB...
    let p = cyclic(20);
    assert_eq!(&p[..5], b"AAAAB");
    // Length is exactly the requested count.
    assert_eq!(p.len(), 20);
    // The first 4 symbols are repeated 'A's by construction.
    assert_eq!(&p[..4], b"AAAA");
}

#[test]
fn cyclic_find_roundtrips_for_each_4byte_window() {
    let p = cyclic(200);
    for i in 0..p.len() - 4 {
        let w = &p[i..i + 4];
        assert_eq!(cyclic_find(w), Some(i), "needle={:?}", w);
    }
}
