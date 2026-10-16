//! Pure matchers shared by configuration validation and the dataplane:
//! HTTP health-check `expect status` grammar (B-H6) and IP/CIDR matching
//! for the PROXY protocol origin allowlist (B-H9/B-E10).
//!
//! No I/O, no dependencies: everything here is deterministic and unit
//! tested so the gate (`validate`) and the runtime agree on one grammar.

use std::net::IpAddr;

/// Expected HTTP status of a health check (`expect status`).
///
/// Grammar (case-insensitive whitespace-tolerant around commas):
/// a comma-separated list of `NNN` codes and `NNN-MMM` inclusive ranges,
/// each in 100–599. Example: `"200-299,301"`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusExpectation {
    ranges: Vec<(u16, u16)>,
}

impl StatusExpectation {
    /// Parses the grammar above. The error names the offending token and
    /// the rule, so callers can report `field + rule` (never a config dump).
    pub fn parse(input: &str) -> Result<Self, String> {
        let mut ranges = Vec::new();
        let trimmed = input.trim();
        if trimmed.is_empty() {
            return Err("must list at least one code or range (rule: \"200\" or \"200-299\" or \"200-204,301\")".to_owned());
        }
        for token in trimmed.split(',') {
            let token = token.trim();
            if token.is_empty() {
                return Err(
                    "empty element between commas (rule: \"200\" or \"200-299\" separated by commas)"
                        .to_owned(),
                );
            }
            let (start, end) = match token.split_once('-') {
                Some((a, b)) => (parse_code(a)?, parse_code(b)?),
                None => {
                    let code = parse_code(token)?;
                    (code, code)
                }
            };
            if start > end {
                return Err(format!(
                    "range {start}-{end} is inverted (rule: start <= end, e.g. \"200-299\")"
                ));
            }
            ranges.push((start, end));
        }
        Ok(Self { ranges })
    }

    /// True when the status code is expected.
    #[must_use]
    pub fn matches(&self, status: u16) -> bool {
        self.ranges.iter().any(|&(a, b)| (a..=b).contains(&status))
    }

    /// Inclusive ranges, in input order (for rendering).
    #[must_use]
    pub fn ranges(&self) -> &[(u16, u16)] {
        &self.ranges
    }
}

fn parse_code(token: &str) -> Result<u16, String> {
    let token = token.trim();
    let code: u16 = token
        .parse()
        .map_err(|_| format!("\"{token}\" is not a status code (rule: 3 digits, 100-599)"))?;
    if !(100..=599).contains(&code) {
        return Err(format!(
            "status {code} out of range (rule: health-check codes are 100-599)"
        ));
    }
    Ok(code)
}

/// One allowlist entry: a single IP or a CIDR block (IPv4 or IPv6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpBlock {
    /// Network address, family-tagged by `is_v6`.
    network: u128,
    /// Prefix length in bits (0–32 / 0–128 depending on family).
    prefix: u8,
    is_v6: bool,
}

impl IpBlock {
    /// Parses `1.2.3.4`, `1.2.3.0/24`, `::1` or `fd00::/8`.
    pub fn parse(input: &str) -> Result<Self, String> {
        let (addr_part, prefix_part) = match input.split_once('/') {
            Some((a, p)) => (a, Some(p)),
            None => (input, None),
        };
        let addr: IpAddr = addr_part.trim().parse().map_err(|_| {
            format!(
                "\"{input}\" is not an IP or CIDR block (rule: \"10.0.0.0/8\", \"192.0.2.1\", \"fd00::/8\")"
            )
        })?;
        let (network, is_v6, max_prefix) = match addr {
            IpAddr::V4(v4) => (u128::from(u32::from(v4)), false, 32_u8),
            IpAddr::V6(v6) => (u128::from(v6), true, 128_u8),
        };
        let prefix = match prefix_part {
            None => max_prefix,
            Some(p) => {
                let p: u8 = p.trim().parse().map_err(|_| {
                    format!(
                        "prefix \"/{p}\" is not a number (rule: /0-/32 for IPv4, /0-/128 for IPv6)"
                    )
                })?;
                if p > max_prefix {
                    return Err(format!(
                        "prefix /{p} exceeds the maximum for {} (rule: /0-/{max_prefix})",
                        if is_v6 { "IPv6" } else { "IPv4" }
                    ));
                }
                p
            }
        };
        let network = Self::mask(network, prefix, Self::width(is_v6));
        Ok(Self {
            network,
            prefix,
            is_v6,
        })
    }

    /// Address width in bits: IPv4 values live in the low 32 bits.
    const fn width(is_v6: bool) -> u32 {
        if is_v6 { 128 } else { 32 }
    }

    /// Clears the host bits of `value` for a `prefix`-long network.
    fn mask(value: u128, prefix: u8, width: u32) -> u128 {
        if prefix == 0 {
            return 0;
        }
        let bits = width - u32::from(prefix);
        value >> bits << bits
    }

    /// True when the address belongs to this block.
    #[must_use]
    pub fn contains(&self, addr: IpAddr) -> bool {
        let (value, is_v6) = match addr {
            IpAddr::V4(v4) => (u128::from(u32::from(v4)), false),
            IpAddr::V6(v6) => (u128::from(v6), true),
        };
        if is_v6 != self.is_v6 {
            return false;
        }
        Self::mask(value, self.prefix, Self::width(self.is_v6)) == self.network
    }
}

/// Non-empty allowlist of [`IpBlock`]s (the PROXY v1 origin allowlist).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpAllowlist {
    blocks: Vec<IpBlock>,
}

impl IpAllowlist {
    /// Parses comma-free entries (one per list element).
    pub fn parse(entries: &[String]) -> Result<Self, String> {
        if entries.is_empty() {
            return Err(
                "must list at least one origin (rule: `proxy_allow = [\"10.0.0.0/8\"]` when `proxy_receive = true`)"
                    .to_owned(),
            );
        }
        let mut blocks = Vec::with_capacity(entries.len());
        for entry in entries {
            blocks.push(IpBlock::parse(entry)?);
        }
        Ok(Self { blocks })
    }

    /// True when any block contains the address.
    #[must_use]
    pub fn contains(&self, addr: IpAddr) -> bool {
        self.blocks.iter().any(|b| b.contains(addr))
    }

    /// Entries, in order (for rendering).
    #[must_use]
    pub fn blocks(&self) -> &[IpBlock] {
        &self.blocks
    }
}

/// Compiled `expect rstring` regex (B-H6).
///
/// Checked once at the gate and reused by the health checker, so
/// validation and runtime share one grammar (the `regex` crate).
#[derive(Debug, Clone)]
pub struct RegexMatcher {
    regex: regex::Regex,
}

impl RegexMatcher {
    /// Compiles the pattern; the error names the rule.
    pub fn parse(pattern: &str) -> Result<Self, String> {
        regex::Regex::new(pattern)
            .map(|regex| Self { regex })
            .map_err(|why| format!("\"{pattern}\" is not a valid regex (rule: {why})"))
    }

    /// True when the pattern matches anywhere in `text`.
    #[must_use]
    pub fn is_match(&self, text: &str) -> bool {
        self.regex.is_match(text)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_codes_ranges_and_lists_match() {
        let one = StatusExpectation::parse("200").expect("code");
        assert!(one.matches(200));
        assert!(!one.matches(201));

        let range = StatusExpectation::parse("200-299").expect("range");
        assert!(range.matches(200) && range.matches(299) && range.matches(250));
        assert!(!range.matches(300) && !range.matches(199));

        let list = StatusExpectation::parse("200-204, 301 ,500").expect("list");
        assert!(list.matches(203) && list.matches(301) && list.matches(500));
        assert!(!list.matches(205));
    }

    #[test]
    fn bad_grammars_name_the_rule() {
        for (input, why) in [
            ("", "empty"),
            ("200,,201", "double comma"),
            ("abc", "not a number"),
            ("99", "below range"),
            ("600", "above range"),
            ("300-200", "inverted"),
            ("200-999", "end above range"),
        ] {
            let err = StatusExpectation::parse(input).expect_err(why);
            assert!(err.contains("rule:"), "error must name the rule: {err}");
        }
    }

    #[test]
    fn cidr_matching_is_exact_per_family() {
        let v4 = IpBlock::parse("10.0.0.0/8").expect("cidr");
        assert!(v4.contains("10.1.2.3".parse().expect("ip")));
        assert!(!v4.contains("11.0.0.1".parse().expect("ip")));
        assert!(
            !v4.contains("fd00::1".parse().expect("ip")),
            "family mismatch"
        );

        let single = IpBlock::parse("192.0.2.1").expect("ip");
        assert!(single.contains("192.0.2.1".parse().expect("ip")));
        assert!(!single.contains("192.0.2.2".parse().expect("ip")));

        let v6 = IpBlock::parse("fd00::/8").expect("cidr6");
        assert!(v6.contains("fd12:3456::1".parse().expect("ip")));
        assert!(!v6.contains("fe80::1".parse().expect("ip")));

        let all = IpBlock::parse("0.0.0.0/0").expect("all");
        assert!(all.contains("203.0.113.9".parse().expect("ip")));
    }

    #[test]
    fn allowlist_rejects_empty_and_matches_any() {
        assert!(
            IpAllowlist::parse(&[]).is_err(),
            "empty allowlist is an error"
        );
        let list = IpAllowlist::parse(&["10.0.0.0/8".to_owned(), "192.0.2.1".to_owned()])
            .expect("allowlist");
        assert!(list.contains("10.9.9.9".parse().expect("ip")));
        assert!(list.contains("192.0.2.1".parse().expect("ip")));
        assert!(!list.contains("192.0.2.2".parse().expect("ip")));
    }

    #[test]
    fn regex_matcher_checks_syntax_and_matches() {
        let ok = RegexMatcher::parse("^ok$").expect("regex");
        assert!(ok.is_match("ok"));
        assert!(!ok.is_match("okay"));

        let err = RegexMatcher::parse("(").expect_err("invalid regex");
        assert!(err.contains("rule:"), "error must name the rule: {err}");
    }

    #[test]
    fn bad_blocks_name_the_rule() {
        for input in ["10.0.0.0/33", "fd00::/129", "nope", "10.0.0.0/x", ""] {
            let err = IpBlock::parse(input).expect_err(input);
            assert!(err.contains("rule:"), "error must name the rule: {err}");
        }
    }
}
