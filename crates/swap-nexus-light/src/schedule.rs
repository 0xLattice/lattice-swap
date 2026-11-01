//! The difficulty schedule: Lattice's `ChainSpec.calculateAsertTarget`
//! (`LatticePoW/ChainSpec+Asert.swift`), ported with the same integer
//! arithmetic, saturation and clamps, so it gives Lattice's target bit for
//! bit.

use crate::U256;

/// What a chain's schedule and spec are pinned to: the spec CID every
/// header must carry, the ASERT anchor (block 1 on Lattice: the builder and
/// validator both take the height-1 ancestor's height, timestamp and
/// target), and the spec's `targetBlockTime` and `halfLife`.
/// [`ChainParams::default`] is Nexus mainnet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainParams {
    pub spec: String,
    pub anchor_height: u64,
    pub anchor_timestamp: i64,
    pub anchor_target: U256,
    /// Milliseconds.
    pub target_block_time: u64,
    /// In blocks of `target_block_time`.
    pub half_life: u64,
}

/// Nexus mainnet's spec, the `spec` link of every mainnet header
/// (`/volumes/<cid>` of block 1 on lattice-mainnet-read, 2026-11-01).
pub const MAINNET_SPEC: &str = "bafyreihdy4bovdbbcdlvgyk2mu3ee22t2hyrvsk6fuwtj2amh4n6nm4kve";
/// Mainnet's ASERT anchor: block 1,
/// `bafyreicyma5qrnosr3doacrduuntwsvqub7dzrtltiggohapt23yia6gwa`.
pub const MAINNET_ANCHOR_HEIGHT: u64 = 1;
/// Block 1's timestamp, milliseconds (2026-10-04T07:41:27.329Z).
pub const MAINNET_ANCHOR_TIMESTAMP: i64 = 1_791_099_687_329;
/// Block 1's target: the maximum.
pub const MAINNET_ANCHOR_TARGET: U256 = [0xff; 32];
/// The mainnet spec's `targetBlockTime`: one hour.
pub const MAINNET_TARGET_BLOCK_TIME: u64 = 3_600_000;
/// The mainnet spec's `halfLife`: 120 blocks, so 120 hours.
pub const MAINNET_HALF_LIFE: u64 = 120;

impl Default for ChainParams {
    fn default() -> Self {
        ChainParams {
            spec: MAINNET_SPEC.to_owned(),
            anchor_height: MAINNET_ANCHOR_HEIGHT,
            anchor_timestamp: MAINNET_ANCHOR_TIMESTAMP,
            anchor_target: MAINNET_ANCHOR_TARGET,
            target_block_time: MAINNET_TARGET_BLOCK_TIME,
            half_life: MAINNET_HALF_LIFE,
        }
    }
}

const FIXED_POINT_BITS: i64 = 16;
const FIXED_POINT_ONE: i64 = 1 << 16;
const MAXIMUM_DOUBLINGS: i64 = 256;
const CUBIC_A: u64 = 195_766_423_245_049;
const CUBIC_B: u64 = 971_821_376;
const CUBIC_C: u64 = 5_127;
const CUBIC_ROUNDING: u64 = 1 << 47;

impl ChainParams {
    /// `calculateAsertTarget(anchor…, blockTimestamp: timestamp,
    /// blockHeight: height)`: the `nextTarget` a block at `height` stamped
    /// `timestamp` must carry (`validateNextTarget` passes the block's own
    /// height, `parent.height + 1`, and its own timestamp).
    pub fn next_target(&self, height: u64, timestamp: i64) -> U256 {
        if height <= self.anchor_height {
            return self.anchor_target;
        }
        let half_life_ms = match self.half_life.checked_mul(self.target_block_time) {
            None => i64::MAX,
            Some(p) => clamp_i64(p),
        };
        if half_life_ms <= 0 {
            return self.anchor_target;
        }
        let anchor = from_be(&self.anchor_target);
        if anchor == [0; 4] {
            return to_be(&ONE);
        }

        let heights = height - self.anchor_height;
        let scheduled = clamp_i64(heights.saturating_mul(self.target_block_time));
        let elapsed = clamp_i64(elapsed_ms(timestamp, self.anchor_timestamp));
        // Both are in [0, i64::MAX], so this cannot overflow (Swift's
        // overflow branch is unreachable).
        let drift = elapsed - scheduled;

        let maximum_drift = i64::MAX / FIXED_POINT_ONE;
        let bounded = drift.clamp(-maximum_drift, maximum_drift);
        // Truncating division, as Swift's `/`.
        let exponent = (bounded * FIXED_POINT_ONE) / half_life_ms;
        // Arithmetic shift: floors, so the fraction is non-negative.
        let doublings = exponent >> FIXED_POINT_BITS;
        let fraction = (exponent & (FIXED_POINT_ONE - 1)) as u64;
        // At most just under u64::MAX at fraction 65535, as in Lattice.
        let cubic = CUBIC_A * fraction
            + CUBIC_B * fraction * fraction
            + CUBIC_C * fraction * fraction * fraction
            + CUBIC_ROUNDING;
        let factor = FIXED_POINT_ONE as u64 + (cubic >> 48);

        if doublings < 0 {
            let halvings = -doublings;
            if halvings >= MAXIMUM_DOUBLINGS - FIXED_POINT_BITS {
                return to_be(&ONE);
            }
            let scaled = mul_div_pow2(&anchor, factor, (halvings + FIXED_POINT_BITS) as u32);
            return to_be(&nonzero(scaled));
        }
        let mut scaled = mul_div_pow2(&anchor, factor, FIXED_POINT_BITS as u32);
        if doublings > 0 {
            if doublings >= MAXIMUM_DOUBLINGS {
                return [0xff; 32];
            }
            for _ in 0..doublings {
                // `scaled <= UInt256.max / 2`.
                if scaled[3] >> 63 != 0 {
                    return [0xff; 32];
                }
                scaled = shl1(&scaled);
            }
        }
        to_be(&nonzero(scaled))
    }
}

/// `Int64(clamping:)` of a `UInt64`.
fn clamp_i64(x: u64) -> i64 {
    i64::try_from(x).unwrap_or(i64::MAX)
}

/// Lattice's `elapsedMilliseconds(later:earlier:)`: 0 unless later.
fn elapsed_ms(later: i64, earlier: i64) -> u64 {
    if later <= earlier {
        return 0;
    }
    (i128::from(later) - i128::from(earlier)) as u64
}

// ---- 256-bit arithmetic, as four little-endian u64 limbs ----

type Limbs = [u64; 4];

const ONE: Limbs = [1, 0, 0, 0];
const MAX: Limbs = [u64::MAX; 4];

fn from_be(x: &U256) -> Limbs {
    let mut out = [0; 4];
    for (i, limb) in out.iter_mut().enumerate() {
        let at = 32 - 8 * (i + 1);
        *limb = u64::from_be_bytes(x[at..at + 8].try_into().unwrap());
    }
    out
}

fn to_be(x: &Limbs) -> U256 {
    let mut out = [0; 32];
    for (i, limb) in x.iter().enumerate() {
        let at = 32 - 8 * (i + 1);
        out[at..at + 8].copy_from_slice(&limb.to_be_bytes());
    }
    out
}

fn nonzero(x: Limbs) -> Limbs {
    if x == [0; 4] {
        ONE
    } else {
        x
    }
}

/// `x >> k`, `k < 256`.
fn shr(x: &Limbs, k: u32) -> Limbs {
    let (words, bits) = ((k / 64) as usize, k % 64);
    let mut out = [0; 4];
    for (i, limb) in out.iter_mut().enumerate() {
        let Some(&lo) = x.get(i + words) else { break };
        *limb = lo >> bits;
        if bits > 0 {
            if let Some(&hi) = x.get(i + words + 1) {
                *limb |= hi << (64 - bits);
            }
        }
    }
    out
}

/// `x mod 2^k`, `k < 256`.
fn low_bits(x: &Limbs, k: u32) -> Limbs {
    let mut out = *x;
    for (i, limb) in out.iter_mut().enumerate() {
        let from = 64 * i as u32;
        if k <= from {
            *limb = 0;
        } else if k - from < 64 {
            *limb &= (1u64 << (k - from)) - 1;
        }
    }
    out
}

/// `x * f`, or `None` past 256 bits.
fn mul_small(x: &Limbs, f: u64) -> Option<Limbs> {
    let mut out = [0; 4];
    let mut carry = 0u128;
    for (o, &limb) in out.iter_mut().zip(x) {
        let p = u128::from(limb) * u128::from(f) + carry;
        *o = p as u64;
        carry = p >> 64;
    }
    (carry == 0).then_some(out)
}

fn add(x: &Limbs, y: &Limbs) -> Option<Limbs> {
    let mut out = [0; 4];
    let mut carry = false;
    for i in 0..4 {
        let (s, c1) = x[i].overflowing_add(y[i]);
        let (s, c2) = s.overflowing_add(carry as u64);
        out[i] = s;
        carry = c1 || c2;
    }
    (!carry).then_some(out)
}

fn shl1(x: &Limbs) -> Limbs {
    let mut out = [0; 4];
    for i in 0..4 {
        out[i] = x[i] << 1;
        if i > 0 {
            out[i] |= x[i - 1] >> 63;
        }
    }
    out
}

/// Lattice's `multiplyDividingSaturating(value, by: f, over: 2^k)` for the
/// two denominators it is called with, both powers of two: the quotient and
/// the remainder are each scaled, saturating at the maximum, and summed.
/// `q * f` overflows exactly when `q > max / f`, so a checked multiply is
/// Swift's comparison.
fn mul_div_pow2(value: &Limbs, f: u64, k: u32) -> Limbs {
    let quotient = shr(value, k);
    let remainder = low_bits(value, k);
    let scaled_quotient = mul_small(&quotient, f).unwrap_or(MAX);
    let scaled_remainder = shr(&mul_small(&remainder, f).unwrap_or(MAX), k);
    add(&scaled_quotient, &scaled_remainder).unwrap_or(MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::wasm_bindgen_test as test;

    fn u(hex: &str) -> U256 {
        let digits = format!("{hex:0>64}");
        let mut out = [0; 32];
        for (i, b) in out.iter_mut().enumerate() {
            *b = u8::from_str_radix(&digits[2 * i..2 * i + 2], 16).unwrap();
        }
        out
    }

    fn params(anchor_target: U256) -> ChainParams {
        ChainParams {
            anchor_target,
            ..ChainParams::default()
        }
    }

    #[test]
    fn limbs_round_trip_and_shift() {
        let x = u("0123456789abcdeffedcba98765432100f1e2d3c4b5a69788796a5b4c3d2e1f0");
        let l = from_be(&x);
        assert_eq!(to_be(&l), x);
        assert_eq!(
            to_be(&shr(&l, 68)),
            u("0123456789abcdeffedcba98765432100f1e2d3c4b5a697")
        );
        assert_eq!(to_be(&low_bits(&l, 68)), u("88796a5b4c3d2e1f0"));
        assert_eq!(to_be(&shr(&l, 255)), [0; 32]);
        assert_eq!(mul_small(&MAX, 2), None);
        assert_eq!(mul_small(&shr(&MAX, 1), 2), Some(shl1(&shr(&MAX, 1))));
    }

    /// Edge cases, checked against a Python transcription of the Swift
    /// (arbitrary-precision integers, so nothing it computes can wrap).
    #[test]
    fn edges() {
        let m = ChainParams::default();
        let (h0, t0) = (MAINNET_ANCHOR_HEIGHT, MAINNET_ANCHOR_TIMESTAMP);
        // At or below the anchor: the anchor's target.
        assert_eq!(m.next_target(h0, t0 + 5), [0xff; 32]);
        assert_eq!(m.next_target(0, 0), [0xff; 32]);
        // On schedule from the maximum: exactly the maximum.
        assert_eq!(m.next_target(h0 + 10, t0 + 36_000_000), [0xff; 32]);
        // Far behind schedule: saturates.
        assert_eq!(m.next_target(h0 + 1, i64::MAX), [0xff; 32]);
        // A timestamp before the anchor reads as zero elapsed; far ahead of
        // schedule the target bottoms out at 1.
        assert_eq!(m.next_target(u64::MAX, i64::MIN), to_be(&ONE));
        assert_eq!(m.next_target(h0 + 1_000_000, t0), to_be(&ONE));
        // One block 1 ms after the anchor (the hardening fold: 0.994 of
        // the maximum, not half of it).
        assert_eq!(
            m.next_target(h0 + 1, t0 + 1),
            u(&format!("fe877{}", "f".repeat(59)))
        );
        // A zero anchor expresses no schedule.
        assert_eq!(params([0; 32]).next_target(5, 0), to_be(&ONE));
        // 2^249 - 1, two doublings harder: exactly a quarter, rounded down.
        let mut odd = [0xff; 32];
        odd[0] = 0x01;
        assert_eq!(
            params(odd).next_target(h0 + 240, t0),
            u(&format!("7{}", "f".repeat(61)))
        );
        // 234 halvings: the remainder's product leaves 256 bits and
        // saturates, so Lattice's answer is `max >> 250` = 63, not the
        // true quotient (under 1). Kept, since it is the consensus value.
        assert_eq!(params(odd).next_target(h0 + 28_080, t0), u("3f"));
        // At the anchor's own height, the anchor's target whatever the time.
        assert_eq!(params(odd).next_target(h0, t0 + 864_000_000), odd);
    }
}
