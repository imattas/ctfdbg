use crate::target::binary::{BinaryInfo, Symbol};

pub fn find_symbol_at(info: &BinaryInfo, address: u64) -> Option<&Symbol> {
    info.symbols.iter().find(|s| s.address == address)
        .or_else(|| info.symbols.iter()
            .filter(|s| s.address <= address && address < s.address + s.size.max(1))
            .max_by_key(|s| s.address))
}
