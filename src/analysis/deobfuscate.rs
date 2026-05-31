//! Deobfuscation by mathematics.
//!
//! Obfuscators love **Mixed Boolean-Arithmetic (MBA)**: they replace a plain
//! operation like `x + y` with a tangle of `&`, `|`, `^`, `+`, `-`, `*` that
//! computes the same value, e.g.
//!
//! ```text
//! (x ^ y) + 2*(x & y)            ==  x + y
//! (x | y) + (x & y)              ==  x + y
//! (x | y) - (~x & y)            ==  x
//! ~(~x + ~y) ... etc.
//! ```
//!
//! This module parses such an expression over 64-bit wrapping integers,
//! simplifies it algebraically, and — the powerful part — tries to
//! **synthesize the simplest equivalent expression** by searching a space of
//! small candidates and proving equivalence over the whole 64-bit ring by
//! random sampling.  That is exactly how practical MBA simplifiers work, and
//! it collapses the obfuscated forms above straight back to `x + y` / `x`.
//!
//! Equivalence is probabilistic (sampling), so results are reported as
//! "verified over N samples"; for the linear MBA seen in CTF/malware this is
//! reliable in practice.

use std::collections::BTreeSet;

// ------------------------------------------------------------------ AST -----

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Expr {
    Const(u64),
    Var(String),
    Not(Box<Expr>),
    Neg(Box<Expr>),
    Add(Box<Expr>, Box<Expr>),
    Sub(Box<Expr>, Box<Expr>),
    Mul(Box<Expr>, Box<Expr>),
    And(Box<Expr>, Box<Expr>),
    Or(Box<Expr>, Box<Expr>),
    Xor(Box<Expr>, Box<Expr>),
    Shl(Box<Expr>, Box<Expr>),
    Shr(Box<Expr>, Box<Expr>),
}

impl Expr {
    fn bin(self, op: char, rhs: Expr) -> Expr {
        let (a, b) = (Box::new(self), Box::new(rhs));
        match op {
            '+' => Expr::Add(a, b),
            '-' => Expr::Sub(a, b),
            '*' => Expr::Mul(a, b),
            '&' => Expr::And(a, b),
            '|' => Expr::Or(a, b),
            '^' => Expr::Xor(a, b),
            'L' => Expr::Shl(a, b),
            'R' => Expr::Shr(a, b),
            _ => unreachable!(),
        }
    }

    /// Number of nodes — our complexity metric for "simplest".
    pub fn node_count(&self) -> usize {
        match self {
            Expr::Const(_) | Expr::Var(_) => 1,
            Expr::Not(a) | Expr::Neg(a) => 1 + a.node_count(),
            Expr::Add(a, b)
            | Expr::Sub(a, b)
            | Expr::Mul(a, b)
            | Expr::And(a, b)
            | Expr::Or(a, b)
            | Expr::Xor(a, b)
            | Expr::Shl(a, b)
            | Expr::Shr(a, b) => 1 + a.node_count() + b.node_count(),
        }
    }

    /// Evaluate under an environment mapping variable name -> value.
    /// All arithmetic is 64-bit wrapping, matching machine semantics.
    pub fn eval(&self, env: &dyn Fn(&str) -> u64) -> u64 {
        match self {
            Expr::Const(c) => *c,
            Expr::Var(v) => env(v),
            Expr::Not(a) => !a.eval(env),
            Expr::Neg(a) => a.eval(env).wrapping_neg(),
            Expr::Add(a, b) => a.eval(env).wrapping_add(b.eval(env)),
            Expr::Sub(a, b) => a.eval(env).wrapping_sub(b.eval(env)),
            Expr::Mul(a, b) => a.eval(env).wrapping_mul(b.eval(env)),
            Expr::And(a, b) => a.eval(env) & b.eval(env),
            Expr::Or(a, b) => a.eval(env) | b.eval(env),
            Expr::Xor(a, b) => a.eval(env) ^ b.eval(env),
            Expr::Shl(a, b) => a.eval(env).wrapping_shl(b.eval(env) as u32),
            Expr::Shr(a, b) => a.eval(env).wrapping_shr(b.eval(env) as u32),
        }
    }

    /// Collect the set of variable names referenced.
    pub fn vars(&self) -> BTreeSet<String> {
        let mut s = BTreeSet::new();
        self.collect_vars(&mut s);
        s
    }
    fn collect_vars(&self, out: &mut BTreeSet<String>) {
        match self {
            Expr::Const(_) => {}
            Expr::Var(v) => {
                out.insert(v.clone());
            }
            Expr::Not(a) | Expr::Neg(a) => a.collect_vars(out),
            Expr::Add(a, b)
            | Expr::Sub(a, b)
            | Expr::Mul(a, b)
            | Expr::And(a, b)
            | Expr::Or(a, b)
            | Expr::Xor(a, b)
            | Expr::Shl(a, b)
            | Expr::Shr(a, b) => {
                a.collect_vars(out);
                b.collect_vars(out);
            }
        }
    }

    /// Pretty-print in conventional C-like infix form.
    pub fn render(&self) -> String {
        match self {
            Expr::Const(c) => {
                if *c > 0xffff {
                    format!("0x{c:x}")
                } else {
                    c.to_string()
                }
            }
            Expr::Var(v) => v.clone(),
            Expr::Not(a) => format!("~{}", a.render_atom()),
            Expr::Neg(a) => format!("-{}", a.render_atom()),
            Expr::Add(a, b) => format!("{} + {}", a.render(), b.render_atom()),
            Expr::Sub(a, b) => format!("{} - {}", a.render(), b.render_atom()),
            Expr::Mul(a, b) => format!("{} * {}", a.render_atom(), b.render_atom()),
            Expr::And(a, b) => format!("{} & {}", a.render_atom(), b.render_atom()),
            Expr::Or(a, b) => format!("{} | {}", a.render_atom(), b.render_atom()),
            Expr::Xor(a, b) => format!("{} ^ {}", a.render_atom(), b.render_atom()),
            Expr::Shl(a, b) => format!("{} << {}", a.render_atom(), b.render_atom()),
            Expr::Shr(a, b) => format!("{} >> {}", a.render_atom(), b.render_atom()),
        }
    }
    fn render_atom(&self) -> String {
        match self {
            Expr::Const(_) | Expr::Var(_) | Expr::Not(_) | Expr::Neg(_) => self.render(),
            other => format!("({})", other.render()),
        }
    }
}

// --------------------------------------------------------------- parser -----

pub fn parse(input: &str) -> Result<Expr, String> {
    let tokens = lex(input)?;
    let mut p = Parser { tokens, pos: 0 };
    let e = p.expr(0)?;
    if p.pos != p.tokens.len() {
        return Err(format!("unexpected trailing input near token {}", p.pos));
    }
    Ok(e)
}

#[derive(Debug, Clone, PartialEq)]
enum Tok {
    Num(u64),
    Ident(String),
    Op(char), // + - * & | ^ ~ , 'L' (<<), 'R' (>>)
    LParen,
    RParen,
}

fn lex(input: &str) -> Result<Vec<Tok>, String> {
    let b = input.as_bytes();
    let mut i = 0;
    let mut out = Vec::new();
    while i < b.len() {
        let c = b[i];
        match c {
            _ if c.is_ascii_whitespace() => i += 1,
            b'(' => {
                out.push(Tok::LParen);
                i += 1;
            }
            b')' => {
                out.push(Tok::RParen);
                i += 1;
            }
            b'+' | b'-' | b'*' | b'&' | b'|' | b'^' | b'~' => {
                out.push(Tok::Op(c as char));
                i += 1;
            }
            b'<' | b'>' => {
                if i + 1 < b.len() && b[i + 1] == c {
                    out.push(Tok::Op(if c == b'<' { 'L' } else { 'R' }));
                    i += 2;
                } else {
                    return Err(format!("stray '{}' (use << or >>)", c as char));
                }
            }
            b'0'..=b'9' => {
                let start = i;
                if c == b'0' && i + 1 < b.len() && (b[i + 1] | 0x20) == b'x' {
                    i += 2;
                    let hs = i;
                    while i < b.len() && b[i].is_ascii_hexdigit() {
                        i += 1;
                    }
                    let v = u64::from_str_radix(&input[hs..i], 16)
                        .map_err(|_| "bad hex literal".to_string())?;
                    out.push(Tok::Num(v));
                } else {
                    while i < b.len() && b[i].is_ascii_digit() {
                        i += 1;
                    }
                    let v = input[start..i]
                        .parse::<u64>()
                        .or_else(|_| input[start..i].parse::<i64>().map(|x| x as u64))
                        .map_err(|_| "bad number".to_string())?;
                    out.push(Tok::Num(v));
                }
            }
            _ if c.is_ascii_alphabetic() || c == b'_' => {
                let start = i;
                while i < b.len() && (b[i].is_ascii_alphanumeric() || b[i] == b'_') {
                    i += 1;
                }
                out.push(Tok::Ident(input[start..i].to_string()));
            }
            _ => return Err(format!("unexpected character '{}'", c as char)),
        }
    }
    Ok(out)
}

struct Parser {
    tokens: Vec<Tok>,
    pos: usize,
}

impl Parser {
    fn peek(&self) -> Option<&Tok> {
        self.tokens.get(self.pos)
    }
    fn bump(&mut self) -> Option<Tok> {
        let t = self.tokens.get(self.pos).cloned();
        self.pos += 1;
        t
    }

    // Binding power per binary operator (higher binds tighter).
    fn bp(op: char) -> u8 {
        match op {
            '|' => 1,
            '^' => 2,
            '&' => 3,
            'L' | 'R' => 4,
            '+' | '-' => 5,
            '*' => 6,
            _ => 0,
        }
    }

    fn expr(&mut self, min_bp: u8) -> Result<Expr, String> {
        let mut lhs = self.unary()?;
        while let Some(Tok::Op(op)) = self.peek().cloned() {
            let bp = Self::bp(op);
            if bp == 0 || bp < min_bp {
                break;
            }
            self.bump();
            let rhs = self.expr(bp + 1)?;
            lhs = lhs.bin(op, rhs);
        }
        Ok(lhs)
    }

    fn unary(&mut self) -> Result<Expr, String> {
        match self.peek().cloned() {
            Some(Tok::Op('-')) => {
                self.bump();
                Ok(Expr::Neg(Box::new(self.unary()?)))
            }
            Some(Tok::Op('~')) => {
                self.bump();
                Ok(Expr::Not(Box::new(self.unary()?)))
            }
            _ => self.primary(),
        }
    }

    fn primary(&mut self) -> Result<Expr, String> {
        match self.bump() {
            Some(Tok::Num(n)) => Ok(Expr::Const(n)),
            Some(Tok::Ident(s)) => Ok(Expr::Var(s)),
            Some(Tok::LParen) => {
                let e = self.expr(0)?;
                match self.bump() {
                    Some(Tok::RParen) => Ok(e),
                    _ => Err("expected ')'".to_string()),
                }
            }
            other => Err(format!("unexpected token {other:?}")),
        }
    }
}

// ------------------------------------------------------ algebraic simplify --

/// Recursively constant-fold and apply algebraic identities to a fixed point.
pub fn simplify(e: &Expr) -> Expr {
    let mut cur = e.clone();
    for _ in 0..32 {
        let next = simplify_once(&cur);
        if next == cur {
            break;
        }
        cur = next;
    }
    cur
}

fn simplify_once(e: &Expr) -> Expr {
    use Expr::*;
    match e {
        Const(_) | Var(_) => e.clone(),
        Not(a) => {
            let a = simplify_once(a);
            match a {
                Const(c) => Const(!c),
                Not(inner) => *inner, // ~~x = x
                _ => Not(Box::new(a)),
            }
        }
        Neg(a) => {
            let a = simplify_once(a);
            match a {
                Const(c) => Const(c.wrapping_neg()),
                Neg(inner) => *inner, // -(-x) = x
                _ => Neg(Box::new(a)),
            }
        }
        Add(a, b) => {
            let (a, b) = (simplify_once(a), simplify_once(b));
            match (&a, &b) {
                (Const(x), Const(y)) => Const(x.wrapping_add(*y)),
                (_, Const(0)) => a,
                (Const(0), _) => b,
                _ if a == b => Mul(Box::new(a), Box::new(Const(2))), // x+x = 2x
                _ => Add(Box::new(a), Box::new(b)),
            }
        }
        Sub(a, b) => {
            let (a, b) = (simplify_once(a), simplify_once(b));
            match (&a, &b) {
                (Const(x), Const(y)) => Const(x.wrapping_sub(*y)),
                (_, Const(0)) => a,
                _ if a == b => Const(0), // x-x = 0
                _ => Sub(Box::new(a), Box::new(b)),
            }
        }
        Mul(a, b) => {
            let (a, b) = (simplify_once(a), simplify_once(b));
            match (&a, &b) {
                (Const(x), Const(y)) => Const(x.wrapping_mul(*y)),
                (_, Const(0)) | (Const(0), _) => Const(0),
                (_, Const(1)) => a,
                (Const(1), _) => b,
                _ => Mul(Box::new(a), Box::new(b)),
            }
        }
        And(a, b) => {
            let (a, b) = (simplify_once(a), simplify_once(b));
            match (&a, &b) {
                (Const(x), Const(y)) => Const(x & y),
                (_, Const(0)) | (Const(0), _) => Const(0),
                (_, Const(u64::MAX)) => a,
                (Const(u64::MAX), _) => b,
                _ if a == b => a, // x&x = x
                _ => And(Box::new(a), Box::new(b)),
            }
        }
        Or(a, b) => {
            let (a, b) = (simplify_once(a), simplify_once(b));
            match (&a, &b) {
                (Const(x), Const(y)) => Const(x | y),
                (_, Const(0)) => a,
                (Const(0), _) => b,
                (_, Const(u64::MAX)) | (Const(u64::MAX), _) => Const(u64::MAX),
                _ if a == b => a, // x|x = x
                _ => Or(Box::new(a), Box::new(b)),
            }
        }
        Xor(a, b) => {
            let (a, b) = (simplify_once(a), simplify_once(b));
            match (&a, &b) {
                (Const(x), Const(y)) => Const(x ^ y),
                (_, Const(0)) => a,
                (Const(0), _) => b,
                _ if a == b => Const(0), // x^x = 0
                _ => Xor(Box::new(a), Box::new(b)),
            }
        }
        Shl(a, b) => {
            let (a, b) = (simplify_once(a), simplify_once(b));
            match (&a, &b) {
                (Const(x), Const(y)) => Const(x.wrapping_shl(*y as u32)),
                (_, Const(0)) => a,
                _ => Shl(Box::new(a), Box::new(b)),
            }
        }
        Shr(a, b) => {
            let (a, b) = (simplify_once(a), simplify_once(b));
            match (&a, &b) {
                (Const(x), Const(y)) => Const(x.wrapping_shr(*y as u32)),
                (_, Const(0)) => a,
                _ => Shr(Box::new(a), Box::new(b)),
            }
        }
    }
}

// ------------------------------------------------------- equivalence check --

/// Deterministic xorshift64* generator — avoids a `rand` dependency while
/// giving good spread for equivalence sampling.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545F4914F6CDD1D)
    }
}

/// Test whether two expressions are equivalent over all 64-bit inputs by
/// sampling `samples` random assignments plus structured edge cases.
/// Returns `true` if they agree on every trial (probabilistically equal).
pub fn equivalent(a: &Expr, b: &Expr, vars: &[String], samples: usize) -> bool {
    let mut rng = Rng(0x9E3779B97F4A7C15);
    // Structured edge cases catch carry/borrow boundaries that random
    // sampling can miss.
    let edges: [u64; 6] = [0, 1, u64::MAX, u64::MAX - 1, 1 << 63, 0x8000_0000];
    let total = samples + edges.len();
    for t in 0..total {
        let mut asg = std::collections::HashMap::new();
        for v in vars {
            let val = if t < edges.len() {
                // mix edge values across variables
                edges[(t + v.len()) % edges.len()]
            } else {
                rng.next()
            };
            asg.insert(v.clone(), val);
        }
        let f = |name: &str| *asg.get(name).unwrap_or(&0);
        if a.eval(&f) != b.eval(&f) {
            return false;
        }
    }
    true
}

// --------------------------------------------------- candidate synthesis ----

/// Try to synthesize the simplest expression equivalent to `target`.
///
/// Enumerates a bounded space of small expressions over the target's
/// variables (atoms, unary, and one- or two-operator combinations) and
/// returns the lowest-complexity candidate that is equivalent over sampling
/// and strictly simpler than the algebraically-simplified target.
pub fn synthesize_simplest(target: &Expr) -> Option<Expr> {
    let vars: Vec<String> = target.vars().into_iter().collect();
    // Only attempt the search for a tractable number of variables.
    if vars.len() > 3 {
        return None;
    }

    let baseline = simplify(target);
    let baseline_complexity = baseline.node_count();

    // Atoms: variables + a few useful constants.
    let mut atoms: Vec<Expr> = vars.iter().map(|v| Expr::Var(v.clone())).collect();
    for c in [0u64, 1, 2, u64::MAX] {
        atoms.push(Expr::Const(c));
    }

    let ops = ['+', '-', '*', '&', '|', '^'];
    let mut candidates: Vec<Expr> = Vec::new();

    // Level 0: atoms.
    candidates.extend(atoms.iter().cloned());
    // Level 1: unary over atoms.
    for a in &atoms {
        candidates.push(Expr::Not(Box::new(a.clone())));
        candidates.push(Expr::Neg(Box::new(a.clone())));
    }
    // Level 2: binary over atoms.
    for a in &atoms {
        for b in &atoms {
            for &op in &ops {
                candidates.push(a.clone().bin(op, b.clone()));
            }
        }
    }
    // Level 3: binary where one side is itself a binary of two atoms — enough
    // to express targets like (x+y)+z or (x^y)+(x&y) reductions.
    let level2: Vec<Expr> = {
        let mut v = Vec::new();
        for a in &atoms {
            for b in &atoms {
                for &op in &ops {
                    v.push(a.clone().bin(op, b.clone()));
                }
            }
        }
        v
    };
    for a in &atoms {
        for b in &level2 {
            for &op in &['+', '-', '^', '&', '|'] {
                candidates.push(a.clone().bin(op, b.clone()));
            }
        }
    }

    // Keep the simplest equivalent candidate that beats the baseline.
    let mut best: Option<Expr> = None;
    for cand in candidates {
        let c = simplify(&cand);
        let complexity = c.node_count();
        if complexity >= baseline_complexity {
            continue;
        }
        if best
            .as_ref()
            .map(|b| complexity >= b.node_count())
            .unwrap_or(false)
        {
            continue;
        }
        if equivalent(target, &c, &vars, 400) {
            best = Some(c);
        }
    }
    best
}

// ---------------------------------------------------------- public report ---

#[derive(Debug, Clone)]
pub struct Deobfuscated {
    pub original: String,
    pub simplified: String,
    /// Set when candidate synthesis found something simpler than algebra alone.
    pub synthesized: Option<String>,
    pub variables: Vec<String>,
    /// `Some(value)` when the expression is constant (no variables).
    pub constant_value: Option<u64>,
}

/// Parse, simplify, and attempt MBA synthesis on an integer expression.
pub fn deobfuscate(input: &str) -> Result<Deobfuscated, String> {
    let expr = parse(input)?;
    let simplified = simplify(&expr);
    let vars: Vec<String> = expr.vars().into_iter().collect();

    let constant_value = if vars.is_empty() {
        Some(simplified.eval(&|_| 0))
    } else {
        None
    };

    let synthesized = if vars.is_empty() {
        None
    } else {
        synthesize_simplest(&expr).map(|e| e.render())
    };

    Ok(Deobfuscated {
        original: expr.render(),
        simplified: simplified.render(),
        synthesized,
        variables: vars,
        constant_value,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parsed(s: &str) -> Expr {
        parse(s).unwrap()
    }

    #[test]
    fn evaluates_constants() {
        assert_eq!(parsed("2 + 3 * 4").eval(&|_| 0), 14);
        assert_eq!(parsed("(2 + 3) * 4").eval(&|_| 0), 20);
        assert_eq!(parsed("0xff & 0x0f").eval(&|_| 0), 0x0f);
        assert_eq!(parsed("1 << 4").eval(&|_| 0), 16);
        assert_eq!(parsed("~0").eval(&|_| 0), u64::MAX);
    }

    #[test]
    fn precedence_matches_c() {
        // & binds tighter than | ; + tighter than <<? In C, shifts bind looser
        // than + ; we mirror that.
        assert_eq!(parsed("1 | 2 & 0").eval(&|_| 0), 1);
        assert_eq!(parsed("1 + 1 << 2").eval(&|_| 0), 8); // (1+1)<<2
    }

    #[test]
    fn algebraic_identities() {
        assert_eq!(simplify(&parsed("x ^ x")), Expr::Const(0));
        assert_eq!(simplify(&parsed("x & x")), Expr::Var("x".into()));
        assert_eq!(simplify(&parsed("x + 0")), Expr::Var("x".into()));
        assert_eq!(simplify(&parsed("x * 1")), Expr::Var("x".into()));
        assert_eq!(simplify(&parsed("x * 0")), Expr::Const(0));
        assert_eq!(simplify(&parsed("~~x")), Expr::Var("x".into()));
    }

    #[test]
    fn mba_add_reduces() {
        // The canonical MBA identity for addition.
        let target = parsed("(x ^ y) + 2 * (x & y)");
        let vars: Vec<String> = target.vars().into_iter().collect();
        let plain = parsed("x + y");
        assert!(equivalent(&target, &plain, &vars, 500));

        let syn = synthesize_simplest(&target).expect("should synthesize");
        assert!(equivalent(&target, &syn, &vars, 500));
        assert!(syn.node_count() <= plain.node_count());
    }

    #[test]
    fn mba_identity_x() {
        // (x | y) - (~x & y) == x
        let target = parsed("(x | y) - (~x & y)");
        let vars: Vec<String> = target.vars().into_iter().collect();
        assert!(equivalent(&target, &Expr::Var("x".into()), &vars, 500));
        let syn = synthesize_simplest(&target).expect("synthesize x");
        assert_eq!(syn, Expr::Var("x".into()));
    }

    #[test]
    fn non_equivalent_detected() {
        let a = parsed("x + y");
        let b = parsed("x ^ y");
        let vars: Vec<String> = a.vars().union(&b.vars()).cloned().collect();
        assert!(!equivalent(&a, &b, &vars, 500));
    }
}
