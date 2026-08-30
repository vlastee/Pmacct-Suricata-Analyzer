use crate::model::{ConnKey, ConnRecord, ProcInfo};
use chrono::{DateTime, DurationRound, TimeDelta, Utc};
use std::collections::HashMap;

/// Folds connection observations into per-minute records. Bounded: beyond `max_entries`
/// new keys are counted as dropped rather than allocated (a runaway process cannot exhaust memory).
pub struct Aggregator {
    entries: HashMap<(i64, ConnKey), ConnRecord>,
    max_entries: usize,
    pub dropped: u64,
}

impl Aggregator {
    pub fn new(max_entries: usize) -> Self {
        Self { entries: HashMap::new(), max_entries, dropped: 0 }
    }

    fn minute_of(t: DateTime<Utc>) -> DateTime<Utc> {
        t.duration_trunc(TimeDelta::minutes(1)).unwrap_or(t)
    }

    /// Record one new connection (or `bytes` more traffic on an existing key) at time `at`.
    pub fn observe(&mut self, at: DateTime<Utc>, key: ConnKey, info: &ProcInfo, bytes: u64, send_cmdline: bool) {
        let minute = Self::minute_of(at);
        let k = (minute.timestamp(), key);
        if let Some(rec) = self.entries.get_mut(&k) {
            rec.count = rec.count.saturating_add(1);
            rec.bytes = rec.bytes.saturating_add(bytes);
            rec.pid = info.pid;
            return;
        }
        if self.entries.len() >= self.max_entries {
            self.dropped += 1;
            return;
        }
        let key = k.1.clone();
        self.entries.insert(
            k,
            ConnRecord {
                minute,
                src: key.src,
                proto: key.proto,
                dst: key.dst,
                dst_port: key.dst_port,
                exe: key.exe,
                name: info.name.clone(),
                user: key.user,
                sha256: info.sha256.clone(),
                pid: info.pid,
                cmdline: if send_cmdline { info.cmdline.clone() } else { String::new() },
                container: key.container,
                count: 1,
                bytes,
            },
        );
    }

    /// Take completed minutes (everything before the minute containing `now`), or everything
    /// when `force` is set (shutdown). Sorted for deterministic batches.
    pub fn drain(&mut self, now: DateTime<Utc>, force: bool) -> Vec<ConnRecord> {
        let current = Self::minute_of(now).timestamp();
        let keys: Vec<_> = self.entries.keys().filter(|(m, _)| force || *m < current).cloned().collect();
        let mut out: Vec<ConnRecord> = keys.into_iter().filter_map(|k| self.entries.remove(&k)).collect();
        out.sort_by(|a, b| (a.minute, &a.exe, &a.dst, a.dst_port).cmp(&(b.minute, &b.exe, &b.dst, b.dst_port)));
        out
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Proto;
    use chrono::TimeZone;

    fn key(dst_port: u16) -> ConnKey {
        ConnKey { src: "10.0.0.5".parse().unwrap(), proto: Proto::Tcp, dst: "1.2.3.4".parse().unwrap(), dst_port, exe: "/usr/bin/curl".into(), user: "petro".into(), container: String::new() }
    }

    #[test]
    fn folds_same_minute_and_drains_completed_minutes() {
        let mut a = Aggregator::new(10);
        let info = ProcInfo { pid: 7, exe: "/usr/bin/curl".into(), name: "curl".into(), user: "petro".into(), sha256: "ab".into(), cmdline: "curl x".into(), container: String::new() };
        let t0 = Utc.with_ymd_and_hms(2026, 8, 29, 21, 15, 10).unwrap();
        a.observe(t0, key(443), &info, 100, false);
        a.observe(t0 + TimeDelta::seconds(20), key(443), &info, 50, false);
        a.observe(t0 + TimeDelta::seconds(70), key(443), &info, 0, true);
        assert_eq!(a.len(), 2);
        // Nothing completed yet at 21:15:30.
        assert!(a.drain(t0 + TimeDelta::seconds(20), false).is_empty());
        // At 21:16:30 the 21:15 minute is complete.
        let done = a.drain(t0 + TimeDelta::seconds(80), false);
        assert_eq!(done.len(), 1);
        assert_eq!(done[0].count, 2);
        assert_eq!(done[0].bytes, 150);
        assert_eq!(done[0].cmdline, "");
        assert_eq!(done[0].minute, Utc.with_ymd_and_hms(2026, 8, 29, 21, 15, 0).unwrap());
        let rest = a.drain(t0, true);
        assert_eq!(rest.len(), 1);
        assert_eq!(rest[0].cmdline, "curl x");
        assert!(a.is_empty());
    }

    #[test]
    fn bounded() {
        let mut a = Aggregator::new(2);
        let info = ProcInfo::default();
        let t = Utc::now();
        for p in 1..=5u16 {
            a.observe(t, key(p), &info, 0, false);
        }
        assert_eq!(a.len(), 2);
        assert_eq!(a.dropped, 3);
    }

    #[test]
    fn wire_format() {
        let rec = ConnRecord { minute: Utc.with_ymd_and_hms(2026, 8, 29, 21, 15, 0).unwrap(), src: "10.0.0.5".parse().unwrap(), proto: Proto::Udp, dst: "1.1.1.1".parse().unwrap(), dst_port: 53, exe: "x".into(), name: "x".into(), user: "u".into(), sha256: String::new(), pid: 1, cmdline: String::new(), container: String::new(), count: 3, bytes: 0 };
        let js = serde_json::to_string(&rec).unwrap();
        assert!(js.contains("\"minute\":\"2026-08-29T21:15:00Z\""));
        assert!(js.contains("\"proto\":\"udp\""));
        assert!(js.contains("\"src\":\"10.0.0.5\""));
        assert!(!js.contains("cmdline"));
        assert!(!js.contains("container"), "empty container is omitted");
    }
}
