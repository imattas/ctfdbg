//! Integration coverage for the MBA deobfuscation engine and codec helpers.

use ctfdbg::analysis::deobfuscate::{deobfuscate, equivalent, parse, simplify, synthesize_simplest, Expr};
use ctfdbg::pwn::encoding;

#[test]
fn mba_addition_collapses_to_x_plus_y() {
    let d = deobfuscate("(x ^ y) + 2 * (x & y)").unwrap();
    // Synthesis should find a 3-node expression equivalent to x + y.
    let syn = d.synthesized.expect("expected a synthesized form");
    let syn_expr = parse(&syn).unwrap();
    let plain = parse("x + y").unwrap();
    let vars: Vec<String> = syn_expr.vars().into_iter().collect();
    assert!(equivalent(&syn_expr, &plain, &vars, 500), "synthesized {syn} != x + y");
}

#[test]
fn constant_expression_folds() {
    let d = deobfuscate("((1 << 8) | 0xff) ^ 0x0f").unwrap();
    assert_eq!(d.constant_value, Some(((1u64 << 8) | 0xff) ^ 0x0f));
}

#[test]
fn algebraic_simplification() {
    assert_eq!(simplify(&parse("(x ^ x) + (y & y)").unwrap()), Expr::Var("y".into()));
}

#[test]
fn xor_subtraction_identity_is_x() {
    // (x | y) - (~x & y) == x ; the engine should recover plain x.
    let syn = synthesize_simplest(&parse("(x | y) - (~x & y)").unwrap()).unwrap();
    assert_eq!(syn, Expr::Var("x".into()));
}

#[test]
fn auto_decode_chain() {
    // base64 over hex over the literal text.
    let inner = encoding::hex_encode(b"the quick brown fox");
    let outer = encoding::base64_encode(inner.as_bytes());
    let steps = encoding::auto_decode(outer.as_bytes(), 8);
    assert_eq!(steps.last().unwrap().output, b"the quick brown fox");
}
