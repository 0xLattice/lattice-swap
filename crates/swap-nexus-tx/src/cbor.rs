//! The subset of cashew's DAG-CBOR that transaction bodies and public keys
//! use. One value has one encoding: integer heads are minimal and map keys
//! are sorted by UTF-8 length, then bytewise.

pub enum Value {
    Int(i128),
    Text(String),
    Array(Vec<Value>),
    Map(Vec<(&'static str, Value)>),
}

impl Value {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.write(&mut out);
        out
    }

    fn write(&self, out: &mut Vec<u8>) {
        match self {
            // Callers pass i64 or u64, so a negative argument (-1 - n) and a
            // non-negative n both fit 64 bits.
            Value::Int(n) if *n < 0 => head(out, 1, (-1 - n) as u64),
            Value::Int(n) => head(out, 0, *n as u64),
            Value::Text(text) => text_head(out, text),
            Value::Array(items) => {
                head(out, 4, items.len() as u64);
                items.iter().for_each(|item| item.write(out));
            }
            Value::Map(entries) => {
                let mut sorted: Vec<_> = entries.iter().collect();
                sorted.sort_by(|(a, _), (b, _)| {
                    (a.len(), a.as_bytes()).cmp(&(b.len(), b.as_bytes()))
                });
                head(out, 5, sorted.len() as u64);
                for (key, value) in sorted {
                    text_head(out, key);
                    value.write(out);
                }
            }
        }
    }
}

fn text_head(out: &mut Vec<u8>, text: &str) {
    head(out, 3, text.len() as u64);
    out.extend_from_slice(text.as_bytes());
}

fn head(out: &mut Vec<u8>, major: u8, n: u64) {
    let major = major << 5;
    match n {
        0..=23 => out.push(major | n as u8),
        24..=0xff => out.extend([major | 24, n as u8]),
        0x100..=0xffff => {
            out.push(major | 25);
            out.extend_from_slice(&(n as u16).to_be_bytes());
        }
        0x1_0000..=0xffff_ffff => {
            out.push(major | 26);
            out.extend_from_slice(&(n as u32).to_be_bytes());
        }
        _ => {
            out.push(major | 27);
            out.extend_from_slice(&n.to_be_bytes());
        }
    }
}
