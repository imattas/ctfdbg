//! Tiny expression parser used for breakpoint conditions.
//!
//! Grammar (recursive descent):
//!   expr     := comparison
//!   comparison := add (("==" | "!=" | "<=" | ">=" | "<" | ">") add)?
//!   add      := mul (("+" | "-") mul)*
//!   mul      := unary (("*" | "/") unary)*
//!   unary    := "-" unary | primary
//!   primary  := number | register | "[" expr "]" | "(" expr ")"
//!   number   := 0x[0-9a-f]+ | [0-9]+
//!   register := identifier
//!
//! Memory dereference `[expr]` reads `pointer_size` bytes.

use crate::debugger::registers::RegisterFile;
use crate::error::{DbgError, DbgResult};

pub trait MemoryReader {
    fn read(&self, address: u64, size: usize) -> DbgResult<Vec<u8>>;
}

pub struct NullMemory;
impl MemoryReader for NullMemory {
    fn read(&self, address: u64, _: usize) -> DbgResult<Vec<u8>> {
        Err(DbgError::Memory { address, message: "no reader".into() })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum Expr {
    Num(u64),
    Reg(String),
    Deref(Box<Expr>),
    Neg(Box<Expr>),
    Bin(BinOp, Box<Expr>, Box<Expr>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinOp { Add, Sub, Mul, Div, Eq, Ne, Lt, Le, Gt, Ge }

pub fn parse(input: &str) -> DbgResult<Expr> {
    let mut p = Parser { src: input.as_bytes(), pos: 0 };
    let e = p.parse_expr()?;
    p.skip_ws();
    if p.pos != p.src.len() {
        return Err(DbgError::Expression(format!(
            "unexpected trailing input at {}", p.pos
        )));
    }
    Ok(e)
}

struct Parser<'a> { src: &'a [u8], pos: usize }

impl<'a> Parser<'a> {
    fn peek(&self) -> Option<u8> { self.src.get(self.pos).copied() }
    fn skip_ws(&mut self) {
        while let Some(c) = self.peek() {
            if c.is_ascii_whitespace() { self.pos += 1; } else { break; }
        }
    }

    fn eat(&mut self, lit: &str) -> bool {
        self.skip_ws();
        if self.src[self.pos..].starts_with(lit.as_bytes()) {
            self.pos += lit.len();
            true
        } else { false }
    }

    fn parse_expr(&mut self) -> DbgResult<Expr> { self.parse_cmp() }

    fn parse_cmp(&mut self) -> DbgResult<Expr> {
        let lhs = self.parse_add()?;
        self.skip_ws();
        for (lit, op) in [("==", BinOp::Eq), ("!=", BinOp::Ne), ("<=", BinOp::Le),
                          (">=", BinOp::Ge), ("<", BinOp::Lt), (">", BinOp::Gt)] {
            if self.eat(lit) {
                let rhs = self.parse_add()?;
                return Ok(Expr::Bin(op, Box::new(lhs), Box::new(rhs)));
            }
        }
        Ok(lhs)
    }

    fn parse_add(&mut self) -> DbgResult<Expr> {
        let mut lhs = self.parse_mul()?;
        loop {
            self.skip_ws();
            if self.eat("+") {
                let rhs = self.parse_mul()?;
                lhs = Expr::Bin(BinOp::Add, Box::new(lhs), Box::new(rhs));
            } else if self.eat("-") {
                let rhs = self.parse_mul()?;
                lhs = Expr::Bin(BinOp::Sub, Box::new(lhs), Box::new(rhs));
            } else { break; }
        }
        Ok(lhs)
    }

    fn parse_mul(&mut self) -> DbgResult<Expr> {
        let mut lhs = self.parse_unary()?;
        loop {
            self.skip_ws();
            if self.eat("*") {
                let rhs = self.parse_unary()?;
                lhs = Expr::Bin(BinOp::Mul, Box::new(lhs), Box::new(rhs));
            } else if self.eat("/") {
                let rhs = self.parse_unary()?;
                lhs = Expr::Bin(BinOp::Div, Box::new(lhs), Box::new(rhs));
            } else { break; }
        }
        Ok(lhs)
    }

    fn parse_unary(&mut self) -> DbgResult<Expr> {
        self.skip_ws();
        if self.eat("-") {
            let e = self.parse_unary()?;
            return Ok(Expr::Neg(Box::new(e)));
        }
        self.parse_primary()
    }

    fn parse_primary(&mut self) -> DbgResult<Expr> {
        self.skip_ws();
        if self.eat("(") {
            let e = self.parse_expr()?;
            if !self.eat(")") {
                return Err(DbgError::Expression("expected )".into()));
            }
            return Ok(e);
        }
        if self.eat("[") {
            let e = self.parse_expr()?;
            if !self.eat("]") {
                return Err(DbgError::Expression("expected ]".into()));
            }
            return Ok(Expr::Deref(Box::new(e)));
        }
        let c = self.peek().ok_or_else(|| DbgError::Expression("unexpected end".into()))?;
        if c.is_ascii_digit() {
            return self.parse_number();
        }
        if c.is_ascii_alphabetic() || c == b'_' {
            return self.parse_ident();
        }
        Err(DbgError::Expression(format!("unexpected char '{}' at {}", c as char, self.pos)))
    }

    fn parse_number(&mut self) -> DbgResult<Expr> {
        let start = self.pos;
        let mut hex = false;
        if self.src[self.pos..].starts_with(b"0x") || self.src[self.pos..].starts_with(b"0X") {
            self.pos += 2;
            hex = true;
        }
        let body_start = self.pos;
        while let Some(c) = self.peek() {
            if hex {
                if !c.is_ascii_hexdigit() { break; }
            } else if !c.is_ascii_digit() {
                break;
            }
            self.pos += 1;
        }
        if self.pos == body_start {
            return Err(DbgError::Expression(format!("bad number at {start}")));
        }
        let text = std::str::from_utf8(&self.src[body_start..self.pos])
            .map_err(|e| DbgError::Expression(e.to_string()))?;
        let val = if hex {
            u64::from_str_radix(text, 16)
        } else {
            text.parse::<u64>()
        }.map_err(|e| DbgError::Expression(e.to_string()))?;
        Ok(Expr::Num(val))
    }

    fn parse_ident(&mut self) -> DbgResult<Expr> {
        let start = self.pos;
        while let Some(c) = self.peek() {
            if c.is_ascii_alphanumeric() || c == b'_' { self.pos += 1; } else { break; }
        }
        let name = std::str::from_utf8(&self.src[start..self.pos])
            .map_err(|e| DbgError::Expression(e.to_string()))?;
        Ok(Expr::Reg(name.to_ascii_lowercase()))
    }
}

pub fn evaluate(expr: &Expr, regs: &RegisterFile, mem: &dyn MemoryReader, ptr_size: usize) -> DbgResult<u64> {
    match expr {
        Expr::Num(n) => Ok(*n),
        Expr::Reg(name) => regs.get(name).ok_or_else(|| {
            DbgError::Expression(format!("unknown register: {name}"))
        }),
        Expr::Deref(inner) => {
            let addr = evaluate(inner, regs, mem, ptr_size)?;
            let bytes = mem.read(addr, ptr_size)?;
            let mut buf = [0u8; 8];
            buf[..bytes.len().min(8)].copy_from_slice(&bytes[..bytes.len().min(8)]);
            Ok(u64::from_le_bytes(buf))
        }
        Expr::Neg(inner) => {
            let v = evaluate(inner, regs, mem, ptr_size)?;
            Ok(0u64.wrapping_sub(v))
        }
        Expr::Bin(op, l, r) => {
            let lv = evaluate(l, regs, mem, ptr_size)?;
            let rv = evaluate(r, regs, mem, ptr_size)?;
            Ok(match op {
                BinOp::Add => lv.wrapping_add(rv),
                BinOp::Sub => lv.wrapping_sub(rv),
                BinOp::Mul => lv.wrapping_mul(rv),
                BinOp::Div => if rv == 0 { 0 } else { lv / rv },
                BinOp::Eq => (lv == rv) as u64,
                BinOp::Ne => (lv != rv) as u64,
                BinOp::Lt => (lv < rv) as u64,
                BinOp::Le => (lv <= rv) as u64,
                BinOp::Gt => (lv > rv) as u64,
                BinOp::Ge => (lv >= rv) as u64,
            })
        }
    }
}
