//! Small network helpers for recon / pentest workflows (IPv4 + CIDR).

/// Parse a dotted-quad IPv4 address into a u32.
pub fn parse_ipv4(s: &str) -> Option<u32> {
    let parts: Vec<&str> = s.trim().split('.').collect();
    if parts.len() != 4 {
        return None;
    }
    let mut v = 0u32;
    for p in parts {
        let octet: u32 = p.parse().ok()?;
        if octet > 255 {
            return None;
        }
        v = (v << 8) | octet;
    }
    Some(v)
}

/// Format a u32 as a dotted-quad IPv4 address.
pub fn fmt_ipv4(v: u32) -> String {
    format!("{}.{}.{}.{}", (v >> 24) & 0xff, (v >> 16) & 0xff, (v >> 8) & 0xff, v & 0xff)
}

#[derive(Debug, Clone)]
pub struct CidrInfo {
    pub prefix: u8,
    pub network: u32,
    pub broadcast: u32,
    pub netmask: u32,
    pub first_host: u32,
    pub last_host: u32,
    pub usable_hosts: u64,
}

/// Parse `a.b.c.d/n` into network details.
pub fn cidr(s: &str) -> Option<CidrInfo> {
    let (ip_s, pfx_s) = s.trim().split_once('/')?;
    let ip = parse_ipv4(ip_s)?;
    let prefix: u8 = pfx_s.trim().parse().ok()?;
    if prefix > 32 {
        return None;
    }
    let netmask: u32 = if prefix == 0 { 0 } else { (!0u32) << (32 - prefix as u32) };
    let network = ip & netmask;
    let broadcast = network | !netmask;
    let total = 1u64 << (32 - prefix as u32);
    let (first_host, last_host, usable) = if prefix >= 31 {
        // /31 and /32 have no separate network/broadcast host split.
        (network, broadcast, total)
    } else {
        (network + 1, broadcast - 1, total - 2)
    };
    Some(CidrInfo {
        prefix,
        network,
        broadcast,
        netmask,
        first_host,
        last_host,
        usable_hosts: usable,
    })
}

/// List host addresses in a CIDR block, capped at `max`.
pub fn hosts(info: &CidrInfo, max: usize) -> Vec<String> {
    let mut out = Vec::new();
    let mut a = info.first_host;
    while a <= info.last_host && out.len() < max {
        out.push(fmt_ipv4(a));
        if a == u32::MAX {
            break;
        }
        a += 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv4_roundtrip() {
        assert_eq!(parse_ipv4("192.168.1.1"), Some(0xC0A80101));
        assert_eq!(fmt_ipv4(0xC0A80101), "192.168.1.1");
        assert_eq!(parse_ipv4("256.0.0.1"), None);
        assert_eq!(parse_ipv4("1.2.3"), None);
    }

    #[test]
    fn cidr_math() {
        let c = cidr("192.168.1.0/24").unwrap();
        assert_eq!(fmt_ipv4(c.network), "192.168.1.0");
        assert_eq!(fmt_ipv4(c.broadcast), "192.168.1.255");
        assert_eq!(fmt_ipv4(c.netmask), "255.255.255.0");
        assert_eq!(fmt_ipv4(c.first_host), "192.168.1.1");
        assert_eq!(fmt_ipv4(c.last_host), "192.168.1.254");
        assert_eq!(c.usable_hosts, 254);
        let h = hosts(&c, 5);
        assert_eq!(h, vec!["192.168.1.1", "192.168.1.2", "192.168.1.3", "192.168.1.4", "192.168.1.5"]);
    }
}
