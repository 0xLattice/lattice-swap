//! The subset of DAG-CBOR that Lattice headers and state nodes use:
//! integers, text, arrays, maps with text keys, and null. Anything else
//! (bytes, tags, floats, indefinite lengths, trailing bytes, a repeated map
//! key) is refused; the bytes are CID-bound, so a refusal only stalls.

use crate::Error;

#[derive(Debug, PartialEq)]
pub enum Value {
    Uint(u64),
    /// `-1 - n`.
    Neg(u64),
    Text(String),
    Array(Vec<Value>),
    Map(Vec<(String, Value)>),
    Null,
}

pub fn decode(bytes: &[u8]) -> Result<Value, Error> {
    let mut at = 0;
    let value = item(bytes, &mut at, 0)?;
    if at != bytes.len() {
        return Err(Error::Malformed("trailing bytes"));
    }
    Ok(value)
}

// Deeper than any Lattice node; bounds the recursion on hostile bytes.
const MAX_DEPTH: usize = 16;

fn item(bytes: &[u8], at: &mut usize, depth: usize) -> Result<Value, Error> {
    if depth > MAX_DEPTH {
        return Err(Error::Malformed("nested too deep"));
    }
    let initial = *take(bytes, at, 1)?.first().unwrap();
    let (major, info) = (initial >> 5, initial & 0x1f);
    if major == 7 {
        return match info {
            22 => Ok(Value::Null),
            _ => Err(Error::Malformed("unsupported simple value")),
        };
    }
    let n = match info {
        0..=23 => info as u64,
        24 => take(bytes, at, 1)?[0] as u64,
        25 => u16::from_be_bytes(take(bytes, at, 2)?.try_into().unwrap()) as u64,
        26 => u32::from_be_bytes(take(bytes, at, 4)?.try_into().unwrap()) as u64,
        27 => u64::from_be_bytes(take(bytes, at, 8)?.try_into().unwrap()),
        _ => return Err(Error::Malformed("indefinite or reserved length")),
    };
    match major {
        0 => Ok(Value::Uint(n)),
        1 => Ok(Value::Neg(n)),
        3 => {
            let text = take(bytes, at, n)?;
            let text =
                core::str::from_utf8(text).map_err(|_| Error::Malformed("text not UTF-8"))?;
            Ok(Value::Text(text.to_owned()))
        }
        4 => {
            let mut items = Vec::new();
            for _ in 0..n {
                items.push(item(bytes, at, depth + 1)?);
            }
            Ok(Value::Array(items))
        }
        5 => {
            let mut entries: Vec<(String, Value)> = Vec::new();
            for _ in 0..n {
                let Value::Text(key) = item(bytes, at, depth + 1)? else {
                    return Err(Error::Malformed("map key not text"));
                };
                if entries.iter().any(|(k, _)| *k == key) {
                    return Err(Error::Malformed("repeated map key"));
                }
                let value = item(bytes, at, depth + 1)?;
                entries.push((key, value));
            }
            Ok(Value::Map(entries))
        }
        _ => Err(Error::Malformed("unsupported CBOR type")),
    }
}

fn take<'a>(bytes: &'a [u8], at: &mut usize, n: u64) -> Result<&'a [u8], Error> {
    let end = usize::try_from(n)
        .ok()
        .and_then(|n| at.checked_add(n))
        .filter(|end| *end <= bytes.len())
        .ok_or(Error::Malformed("truncated CBOR"))?;
    let out = &bytes[*at..end];
    *at = end;
    Ok(out)
}

impl Value {
    /// The value under `key` of a map; `None` when absent or not a map.
    pub fn get(&self, key: &str) -> Option<&Value> {
        match self {
            Value::Map(entries) => entries.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }
}
