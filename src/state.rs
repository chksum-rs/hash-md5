//! Module contains items related to the [`State`] structure which allows to the direct MD5 state manipulation.
//!
//! # Example
//!
//! ```rust
//! use chksum_hash_md5 as md5;
//!
//! // Create new state
//! let mut state = md5::state::default();
//!
//! // By default it returns initialization values
//! assert_eq!(
//!     state.digest(),
//!     [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476]
//! );
//!
//! // Manually create block of data with proper padding
//! let data = [
//!     u32::from_le_bytes([0x80, 0x00, 0x00, 0x00]),
//!     u32::from_le_bytes([0x00, 0x00, 0x00, 0x00]),
//!     # u32::from_le_bytes([0x00, 0x00, 0x00, 0x00]),
//!     # u32::from_le_bytes([0x00, 0x00, 0x00, 0x00]),
//!     # u32::from_le_bytes([0x00, 0x00, 0x00, 0x00]),
//!     # u32::from_le_bytes([0x00, 0x00, 0x00, 0x00]),
//!     # u32::from_le_bytes([0x00, 0x00, 0x00, 0x00]),
//!     # u32::from_le_bytes([0x00, 0x00, 0x00, 0x00]),
//!     # u32::from_le_bytes([0x00, 0x00, 0x00, 0x00]),
//!     # u32::from_le_bytes([0x00, 0x00, 0x00, 0x00]),
//!     # u32::from_le_bytes([0x00, 0x00, 0x00, 0x00]),
//!     # u32::from_le_bytes([0x00, 0x00, 0x00, 0x00]),
//!     # u32::from_le_bytes([0x00, 0x00, 0x00, 0x00]),
//!     # u32::from_le_bytes([0x00, 0x00, 0x00, 0x00]),
//!     # u32::from_le_bytes([0x00, 0x00, 0x00, 0x00]),
//!     // ...
//!     u32::from_le_bytes([0x00, 0x00, 0x00, 0x00]),
//! ];
//!
//! // Update state and own new value
//! state = state.update(data);
//!
//! // Proper digest of empty input
//! assert_eq!(
//!     state.digest(),
//!     [0xD98C1DD4, 0x04B2008F, 0x980980E9, 0x7E42F8EC]
//! );
//!
//! // Reset state to initial values
//! state = state.reset();
//! assert_eq!(
//!     state.digest(),
//!     [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476]
//! );
//! ```
//!
//! # Warning
//!
//! The [`State`] structure does not modify internal state, each function returns a new state that must be used.

use crate::block::LENGTH_DWORDS as BLOCK_LENGTH_DWORDS;
use crate::digest::LENGTH_DWORDS as DIGEST_LENGTH_DWORDS;

#[allow(clippy::unreadable_literal)]
const A: u32 = 0x67452301;
#[allow(clippy::unreadable_literal)]
const B: u32 = 0xEFCDAB89;
#[allow(clippy::unreadable_literal)]
const C: u32 = 0x98BADCFE;
#[allow(clippy::unreadable_literal)]
const D: u32 = 0x10325476;

#[allow(clippy::unreadable_literal)]
#[rustfmt::skip]
const CONSTS: [u32; 64] = [
    0xD76AA478, 0xE8C7B756, 0x242070DB, 0xC1BDCEEE,
    0xF57C0FAF, 0x4787C62A, 0xA8304613, 0xFD469501,
    0x698098D8, 0x8B44F7AF, 0xFFFF5BB1, 0x895CD7BE,
    0x6B901122, 0xFD987193, 0xA679438E, 0x49B40821,
    0xF61E2562, 0xC040B340, 0x265E5A51, 0xE9B6C7AA,
    0xD62F105D, 0x02441453, 0xD8A1E681, 0xE7D3FBC8,
    0x21E1CDE6, 0xC33707D6, 0xF4D50D87, 0x455A14ED,
    0xA9E3E905, 0xFCEFA3F8, 0x676F02D9, 0x8D2A4C8A,
    0xFFFA3942, 0x8771F681, 0x6D9D6122, 0xFDE5380C,
    0xA4BEEA44, 0x4BDECFA9, 0xF6BB4B60, 0xBEBFBC70,
    0x289B7EC6, 0xEAA127FA, 0xD4EF3085, 0x04881D05,
    0xD9D4D039, 0xE6DB99E5, 0x1FA27CF8, 0xC4AC5665,
    0xF4292244, 0x432AFF97, 0xAB9423A7, 0xFC93A039,
    0x655B59C3, 0x8F0CCC92, 0xFFEFF47D, 0x85845DD1,
    0x6FA87E4F, 0xFE2CE6E0, 0xA3014314, 0x4E0811A1,
    0xF7537E82, 0xBD3AF235, 0x2AD7D2BB, 0xEB86D391,
];

#[allow(clippy::unreadable_literal)]
#[rustfmt::skip]
const SHIFTS: [u8; 16] = [
    0x07, 0x0C, 0x11, 0x16,
    0x05, 0x09, 0x0E, 0x14,
    0x04, 0x0B, 0x10, 0x17,
    0x06, 0x0A, 0x0F, 0x15,
];

/// Create a new state.
#[must_use]
pub const fn new() -> State {
    State::new()
}

/// Creates a default state.
#[must_use]
pub fn default() -> State {
    State::default()
}

/// A low-level hash state.
///
/// Check [`state`](self) module for usage examples.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
pub struct State {
    pub(crate) a: u32,
    pub(crate) b: u32,
    pub(crate) c: u32,
    pub(crate) d: u32,
}

impl State {
    /// Creates a new state.
    #[must_use]
    pub const fn new() -> Self {
        Self { a: A, b: B, c: C, d: D }
    }

    /// Returns modified state with the passed data.
    ///
    /// **Warning!** Input block must be in the little-endian byte order.
    #[must_use]
    pub const fn update(&self, block: [u32; BLOCK_LENGTH_DWORDS]) -> Self {
        let Self { a, b, c, d } = *self;

        // Round 1

        const fn f(x: u32, y: u32, z: u32) -> u32 {
            (x & y) | (!x & z)
        }

        const fn ff(a: u32, b: u32, c: u32, d: u32, data: u32, shl: u8, constant: u32) -> u32 {
            a.wrapping_add(f(b, c, d))
                .wrapping_add(data)
                .wrapping_add(constant)
                .rotate_left(shl as u32)
                .wrapping_add(b)
        }

        let a = ff(a, b, c, d, block[0x0], SHIFTS[0x0], CONSTS[0x00]);
        let d = ff(d, a, b, c, block[0x1], SHIFTS[0x1], CONSTS[0x01]);
        let c = ff(c, d, a, b, block[0x2], SHIFTS[0x2], CONSTS[0x02]);
        let b = ff(b, c, d, a, block[0x3], SHIFTS[0x3], CONSTS[0x03]);
        let a = ff(a, b, c, d, block[0x4], SHIFTS[0x0], CONSTS[0x04]);
        let d = ff(d, a, b, c, block[0x5], SHIFTS[0x1], CONSTS[0x05]);
        let c = ff(c, d, a, b, block[0x6], SHIFTS[0x2], CONSTS[0x06]);
        let b = ff(b, c, d, a, block[0x7], SHIFTS[0x3], CONSTS[0x07]);
        let a = ff(a, b, c, d, block[0x8], SHIFTS[0x0], CONSTS[0x08]);
        let d = ff(d, a, b, c, block[0x9], SHIFTS[0x1], CONSTS[0x09]);
        let c = ff(c, d, a, b, block[0xA], SHIFTS[0x2], CONSTS[0x0A]);
        let b = ff(b, c, d, a, block[0xB], SHIFTS[0x3], CONSTS[0x0B]);
        let a = ff(a, b, c, d, block[0xC], SHIFTS[0x0], CONSTS[0x0C]);
        let d = ff(d, a, b, c, block[0xD], SHIFTS[0x1], CONSTS[0x0D]);
        let c = ff(c, d, a, b, block[0xE], SHIFTS[0x2], CONSTS[0x0E]);
        let b = ff(b, c, d, a, block[0xF], SHIFTS[0x3], CONSTS[0x0F]);

        // Round 2

        const fn g(x: u32, y: u32, z: u32) -> u32 {
            (x & z) | (y & !z)
        }

        const fn gg(a: u32, b: u32, c: u32, d: u32, data: u32, shl: u8, constant: u32) -> u32 {
            a.wrapping_add(g(b, c, d))
                .wrapping_add(data)
                .wrapping_add(constant)
                .rotate_left(shl as u32)
                .wrapping_add(b)
        }

        let a = gg(a, b, c, d, block[0x1], SHIFTS[0x4], CONSTS[0x10]);
        let d = gg(d, a, b, c, block[0x6], SHIFTS[0x5], CONSTS[0x11]);
        let c = gg(c, d, a, b, block[0xB], SHIFTS[0x6], CONSTS[0x12]);
        let b = gg(b, c, d, a, block[0x0], SHIFTS[0x7], CONSTS[0x13]);
        let a = gg(a, b, c, d, block[0x5], SHIFTS[0x4], CONSTS[0x14]);
        let d = gg(d, a, b, c, block[0xA], SHIFTS[0x5], CONSTS[0x15]);
        let c = gg(c, d, a, b, block[0xF], SHIFTS[0x6], CONSTS[0x16]);
        let b = gg(b, c, d, a, block[0x4], SHIFTS[0x7], CONSTS[0x17]);
        let a = gg(a, b, c, d, block[0x9], SHIFTS[0x4], CONSTS[0x18]);
        let d = gg(d, a, b, c, block[0xE], SHIFTS[0x5], CONSTS[0x19]);
        let c = gg(c, d, a, b, block[0x3], SHIFTS[0x6], CONSTS[0x1A]);
        let b = gg(b, c, d, a, block[0x8], SHIFTS[0x7], CONSTS[0x1B]);
        let a = gg(a, b, c, d, block[0xD], SHIFTS[0x4], CONSTS[0x1C]);
        let d = gg(d, a, b, c, block[0x2], SHIFTS[0x5], CONSTS[0x1D]);
        let c = gg(c, d, a, b, block[0x7], SHIFTS[0x6], CONSTS[0x1E]);
        let b = gg(b, c, d, a, block[0xC], SHIFTS[0x7], CONSTS[0x1F]);

        // Round 3

        const fn h(x: u32, y: u32, z: u32) -> u32 {
            x ^ y ^ z
        }

        const fn hh(a: u32, b: u32, c: u32, d: u32, data: u32, shl: u8, constant: u32) -> u32 {
            a.wrapping_add(h(b, c, d))
                .wrapping_add(data)
                .wrapping_add(constant)
                .rotate_left(shl as u32)
                .wrapping_add(b)
        }

        let a = hh(a, b, c, d, block[0x5], SHIFTS[0x8], CONSTS[0x20]);
        let d = hh(d, a, b, c, block[0x8], SHIFTS[0x9], CONSTS[0x21]);
        let c = hh(c, d, a, b, block[0xB], SHIFTS[0xA], CONSTS[0x22]);
        let b = hh(b, c, d, a, block[0xE], SHIFTS[0xB], CONSTS[0x23]);
        let a = hh(a, b, c, d, block[0x1], SHIFTS[0x8], CONSTS[0x24]);
        let d = hh(d, a, b, c, block[0x4], SHIFTS[0x9], CONSTS[0x25]);
        let c = hh(c, d, a, b, block[0x7], SHIFTS[0xA], CONSTS[0x26]);
        let b = hh(b, c, d, a, block[0xA], SHIFTS[0xB], CONSTS[0x27]);
        let a = hh(a, b, c, d, block[0xD], SHIFTS[0x8], CONSTS[0x28]);
        let d = hh(d, a, b, c, block[0x0], SHIFTS[0x9], CONSTS[0x29]);
        let c = hh(c, d, a, b, block[0x3], SHIFTS[0xA], CONSTS[0x2A]);
        let b = hh(b, c, d, a, block[0x6], SHIFTS[0xB], CONSTS[0x2B]);
        let a = hh(a, b, c, d, block[0x9], SHIFTS[0x8], CONSTS[0x2C]);
        let d = hh(d, a, b, c, block[0xC], SHIFTS[0x9], CONSTS[0x2D]);
        let c = hh(c, d, a, b, block[0xF], SHIFTS[0xA], CONSTS[0x2E]);
        let b = hh(b, c, d, a, block[0x2], SHIFTS[0xB], CONSTS[0x2F]);

        // Round 4

        const fn i(x: u32, y: u32, z: u32) -> u32 {
            y ^ (x | !z)
        }

        const fn ii(a: u32, b: u32, c: u32, d: u32, data: u32, shl: u8, constant: u32) -> u32 {
            a.wrapping_add(i(b, c, d))
                .wrapping_add(data)
                .wrapping_add(constant)
                .rotate_left(shl as u32)
                .wrapping_add(b)
        }

        let a = ii(a, b, c, d, block[0x0], SHIFTS[0xC], CONSTS[0x30]);
        let d = ii(d, a, b, c, block[0x7], SHIFTS[0xD], CONSTS[0x31]);
        let c = ii(c, d, a, b, block[0xE], SHIFTS[0xE], CONSTS[0x32]);
        let b = ii(b, c, d, a, block[0x5], SHIFTS[0xF], CONSTS[0x33]);
        let a = ii(a, b, c, d, block[0xC], SHIFTS[0xC], CONSTS[0x34]);
        let d = ii(d, a, b, c, block[0x3], SHIFTS[0xD], CONSTS[0x35]);
        let c = ii(c, d, a, b, block[0xA], SHIFTS[0xE], CONSTS[0x36]);
        let b = ii(b, c, d, a, block[0x1], SHIFTS[0xF], CONSTS[0x37]);
        let a = ii(a, b, c, d, block[0x8], SHIFTS[0xC], CONSTS[0x38]);
        let d = ii(d, a, b, c, block[0xF], SHIFTS[0xD], CONSTS[0x39]);
        let c = ii(c, d, a, b, block[0x6], SHIFTS[0xE], CONSTS[0x3A]);
        let b = ii(b, c, d, a, block[0xD], SHIFTS[0xF], CONSTS[0x3B]);
        let a = ii(a, b, c, d, block[0x4], SHIFTS[0xC], CONSTS[0x3C]);
        let d = ii(d, a, b, c, block[0xB], SHIFTS[0xD], CONSTS[0x3D]);
        let c = ii(c, d, a, b, block[0x2], SHIFTS[0xE], CONSTS[0x3E]);
        let b = ii(b, c, d, a, block[0x9], SHIFTS[0xF], CONSTS[0x3F]);

        // Update

        let a = a.wrapping_add(self.a);
        let b = b.wrapping_add(self.b);
        let c = c.wrapping_add(self.c);
        let d = d.wrapping_add(self.d);

        // Return

        Self { a, b, c, d }
    }

    /// Returns a new state with initial values.
    #[must_use]
    pub const fn reset(self) -> Self {
        Self::new()
    }

    /// Returns a digest.
    #[must_use]
    pub const fn digest(&self) -> [u32; DIGEST_LENGTH_DWORDS] {
        let Self { a, b, c, d } = *self;
        [a, b, c, d]
    }
}

impl Default for State {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_empty() {
        let digest = new().digest();
        assert_eq!(digest, [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476]);
    }

    #[test]
    fn default_empty() {
        let digest = default().digest();
        assert_eq!(digest, [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476]);
    }

    #[test]
    fn new_zeros() {
        let block = [
            u32::from_le_bytes([0x80, 0x00, 0x00, 0x00]),
            u32::from_le_bytes([0x00, 0x00, 0x00, 0x00]),
            u32::from_le_bytes([0x00, 0x00, 0x00, 0x00]),
            u32::from_le_bytes([0x00, 0x00, 0x00, 0x00]),
            u32::from_le_bytes([0x00, 0x00, 0x00, 0x00]),
            u32::from_le_bytes([0x00, 0x00, 0x00, 0x00]),
            u32::from_le_bytes([0x00, 0x00, 0x00, 0x00]),
            u32::from_le_bytes([0x00, 0x00, 0x00, 0x00]),
            u32::from_le_bytes([0x00, 0x00, 0x00, 0x00]),
            u32::from_le_bytes([0x00, 0x00, 0x00, 0x00]),
            u32::from_le_bytes([0x00, 0x00, 0x00, 0x00]),
            u32::from_le_bytes([0x00, 0x00, 0x00, 0x00]),
            u32::from_le_bytes([0x00, 0x00, 0x00, 0x00]),
            u32::from_le_bytes([0x00, 0x00, 0x00, 0x00]),
            u32::from_le_bytes([0x00, 0x00, 0x00, 0x00]),
            u32::from_le_bytes([0x00, 0x00, 0x00, 0x00]),
        ];
        let digest = new().update(block).digest();
        assert_eq!(digest, [0xD98C1DD4, 0x04B2008F, 0x980980E9, 0x7E42F8EC]);
    }
}
