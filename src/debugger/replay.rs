//! Ordered static PCs from a Lens trace export. Only the cursor changes during replay.

use serde::de::{self, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use std::fmt;
use std::fs::OpenOptions;
use std::io::Read;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

pub(super) const MAX_STEPS: usize = 5000;
const MAX_BYTES: u64 = 8 * 1024 * 1024;
const TEXT_HEADER: &str = "# Lens instruction trace";
const TEXT_COLUMNS: &str = "# columns: step address hits function signal";

pub(super) struct Replay {
    addresses: Vec<u64>,
    cursor: usize,
}

impl Replay {
    pub(super) fn open(path: &Path) -> Result<Self, String> {
        // A selected pipe should never block the UI while we check its file type.
        let file = OpenOptions::new().read(true).custom_flags(libc::O_NONBLOCK)
            .open(path).map_err(|e| format!("Couldn't open trace: {e}"))?;
        let metadata = file.metadata().map_err(|e| format!("Couldn't inspect trace: {e}"))?;
        if !metadata.is_file() {
            return Err("Choose a regular trace file.".into());
        }
        if metadata.len() > MAX_BYTES {
            return Err("Trace exceeds the 8 MiB import limit.".into());
        }
        let mut bytes = Vec::new();
        file.take(MAX_BYTES + 1).read_to_end(&mut bytes)
            .map_err(|e| format!("Couldn't read trace: {e}"))?;
        Self::parse(&bytes)
    }

    fn parse(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() as u64 > MAX_BYTES {
            return Err("Trace exceeds the 8 MiB import limit.".into());
        }
        let text = std::str::from_utf8(bytes).map_err(|_| "Trace must be UTF-8.")?;
        let addresses = if text.trim_start().starts_with('{') {
            let export: JsonTrace = serde_json::from_str(text)
                .map_err(|e| format!("Invalid trace JSON: {e}"))?;
            if export.schema != "lens.dynamic-trace.v1" {
                return Err("Expected the lens.dynamic-trace.v1 schema.".into());
            }
            if export.entries != export.records.len() {
                return Err("Trace entry count does not match its records.".into());
            }
            export.records
        } else {
            text_addresses(text)?
        };
        if addresses.is_empty() {
            return Err("Trace contains no instructions.".into());
        }
        Ok(Self { addresses, cursor: 0 })
    }

    pub(super) fn pc(&self) -> u64 { self.addresses[self.cursor] }
    pub(super) fn step_index(&self) -> usize { self.cursor }
    pub(super) fn len(&self) -> usize { self.addresses.len() }
    pub(super) fn back(&mut self) { self.cursor = self.cursor.saturating_sub(1); }
    pub(super) fn step(&mut self) { self.cursor = (self.cursor + 1).min(self.len() - 1); }
}

fn push_step(addresses: &mut Vec<u64>, step: usize, address: u64) -> Result<(), &'static str> {
    if addresses.len() == MAX_STEPS {
        return Err("Trace exceeds the 5,000 instruction limit.");
    }
    if step != addresses.len() {
        return Err("Trace steps must be consecutive and start at zero.");
    }
    addresses.push(address);
    Ok(())
}

fn text_addresses(text: &str) -> Result<Vec<u64>, String> {
    let mut lines = text.lines();
    if lines.next() != Some(TEXT_HEADER) || lines.next() != Some(TEXT_COLUMNS) {
        return Err("Expected a Lens text or JSON instruction trace.".into());
    }
    let mut addresses = Vec::new();
    for (index, line) in lines.enumerate() {
        let mut fields = line.split_ascii_whitespace();
        let step = fields.next().and_then(|s| s.parse::<usize>().ok());
        let address = fields.next().filter(|s| s.len() == 16 && s.bytes().all(|b| b.is_ascii_hexdigit()))
            .and_then(|s| u64::from_str_radix(s, 16).ok());
        let hits = fields.next().and_then(|s| s.strip_prefix("hits="))
            .and_then(|s| s.parse::<usize>().ok());
        let (Some(step), Some(address), Some(1..=MAX_STEPS)) = (step, address, hits) else {
            return Err(format!("Invalid instruction record on line {}.", index + 3));
        };
        push_step(&mut addresses, step, address)?;
    }
    Ok(addresses)
}

#[derive(Deserialize)]
struct JsonTrace {
    schema: String,
    entries: usize,
    #[serde(deserialize_with = "read_records")]
    records: Vec<u64>,
}

#[derive(Deserialize)]
struct Record {
    step: usize,
    address: u64,
}

fn read_records<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u64>, D::Error> {
    struct Records;
    impl<'de> Visitor<'de> for Records {
        type Value = Vec<u64>;

        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("an array of Lens trace records")
        }

        fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Vec<u64>, A::Error> {
            let mut addresses = Vec::new();
            while let Some(record) = seq.next_element::<Record>()? {
                push_step(&mut addresses, record.step, record.address)
                    .map_err(<A::Error as de::Error>::custom)?;
            }
            Ok(addresses)
        }
    }
    deserializer.deserialize_seq(Records)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn both_exports_replay_repeated_static_pcs_in_order() {
        let text = format!("{TEXT_HEADER}\r\n{TEXT_COLUMNS}\r\n\
            000000  FFFFFFFFFFFFFFFF  hits=2  main  heuristic: example\r\n\
            000001  FFFFFFFFFFFFFFFF  hits=2  main  heuristic: example\r\n\
            000002  0000000000000000  hits=1\r\n");
        let json = r#"{"schema":"lens.dynamic-trace.v1","entries":3,"events":["stopped"],
            "records":[{"step":0,"address":18446744073709551615,"hits":2,"function":"main"},
                       {"step":1,"address":18446744073709551615,"hits":2,"function":"main"},
                       {"step":2,"address":0,"hits":1,"function":null}]}"#;
        for export in [text.as_bytes(), json.as_bytes()] {
            let mut replay = Replay::parse(export).unwrap();
            replay.back();
            assert_eq!((replay.step_index(), replay.pc()), (0, u64::MAX));
            replay.step();
            assert_eq!((replay.step_index(), replay.pc()), (1, u64::MAX));
            replay.step();
            replay.step();
            assert_eq!((replay.step_index(), replay.pc()), (2, 0));
            replay.back();
            assert_eq!((replay.step_index(), replay.pc()), (1, u64::MAX));
        }
    }

    #[test]
    fn rejects_invalid_exports_as_a_whole() {
        let json = r#"{"schema":"lens.dynamic-trace.v1","entries":1,"records":[{"step":0,"address":17}]}"#;
        for invalid in [
            json.replace("v1", "v2"),
            json.replace("\"entries\":1", "\"entries\":0"),
            json.replace("\"step\":0", "\"step\":1"),
            json.replace("17", "-1"),
            json.replace("17", "18446744073709551616"),
            format!("{json} trailing"),
            format!("{TEXT_HEADER}\n{TEXT_COLUMNS}\n"),
            format!("{TEXT_HEADER}\n{TEXT_COLUMNS}\n000000  0000000000000000  hits=1\nmalformed"),
        ] {
            assert!(Replay::parse(invalid.as_bytes()).is_err(), "{invalid}");
        }
    }

    #[test]
    fn enforces_byte_and_record_limits() {
        assert!(Replay::parse(&vec![b' '; MAX_BYTES as usize + 1]).is_err());
        let mut text = format!("{TEXT_HEADER}\n{TEXT_COLUMNS}\n");
        for step in 0..MAX_STEPS {
            text.push_str(&format!("{step:06}  0000000000000010  hits={MAX_STEPS}\n"));
        }
        assert_eq!(Replay::parse(text.as_bytes()).unwrap().len(), MAX_STEPS);
        text.push_str("005000  0000000000000020  hits=1\n");
        assert!(Replay::parse(text.as_bytes()).is_err());
    }
}
