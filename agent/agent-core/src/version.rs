//! Semantic-ish version comparison ("0.2.0" > "0.1.9"); non-numeric parts compare as 0.
pub fn parse(v: &str) -> Vec<u64> {
    v.trim().trim_start_matches('v').split(['.', '-', '+']).map(|p| p.parse::<u64>().unwrap_or(0)).collect()
}

/// True when `candidate` is strictly newer than `current`.
pub fn newer(candidate: &str, current: &str) -> bool {
    let (a, b) = (parse(candidate), parse(current));
    let n = a.len().max(b.len());
    for i in 0..n {
        let (x, y) = (*a.get(i).unwrap_or(&0), *b.get(i).unwrap_or(&0));
        if x != y {
            return x > y;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::newer;
    #[test]
    fn compare() {
        assert!(newer("0.2.0", "0.1.0"));
        assert!(newer("0.10.0", "0.9.9"));
        assert!(newer("1.0.0", "0.99.99"));
        assert!(!newer("0.2.0", "0.2.0"));
        assert!(!newer("0.1.9", "0.2.0"));
        assert!(newer("0.2.1", "0.2"));
        assert!(!newer("", "0.1.0"));
    }
}
