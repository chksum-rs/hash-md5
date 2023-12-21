//! Module contains items related to the [`Digest`] structure.
//!
//! # Example
//!
//! ```rust
//! use chksum_hash_md5 as md5;
//!
//! // Digest bytes
//! #[rustfmt::skip]
//! let digest = [
//!     0xD4, 0x1D, 0x8C, 0xD9,
//!     0x8F, 0x00, 0xB2, 0x04,
//!     0xE9, 0x80, 0x09, 0x98,
//!     0xEC, 0xF8, 0x42, 0x7E,
//! ];
//!
//! // Create new digest
//! let digest = md5::digest::new(digest);
//!
//! // Print digest (by default it uses hex lowercase format)
//! println!("digest {}", digest);
//!
//! // You can also specify which format you prefer
//! println!("digest {:x}", digest);
//! println!("digest {:X}", digest);
//!
//! // Turn into byte slice
//! let bytes = digest.as_bytes();
//!
//! // Get inner bytes
//! let digest = digest.into_inner();
//!
//! // Should be same
//! assert_eq!(bytes, &digest[..]);
//! ```

use std::fmt::{self, Display, Formatter, LowerHex, UpperHex};
use std::num::ParseIntError;

use chksum_hash_core as core;

/// Digest length in bits.
pub const LENGTH_BITS: usize = 128;
/// Digest length in bytes.
pub const LENGTH_BYTES: usize = LENGTH_BITS / 8;
/// Digest length in words (double bytes).
pub const LENGTH_WORDS: usize = LENGTH_BYTES / 2;
/// Digest length in double words (quadruple bytes).
pub const LENGTH_DWORDS: usize = LENGTH_WORDS / 2;
/// Digest length in hexadecimal format.
pub const LENGTH_HEX: usize = LENGTH_BYTES * 2;

/// Creates a new [`Digest`].
#[must_use]
pub fn new(digest: [u8; LENGTH_BYTES]) -> Digest {
    Digest::new(digest)
}

/// A hash digest.
///
/// Check [`digest`](self) module for usage examples.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Digest([u8; LENGTH_BYTES]);

impl Digest {
    /// Creates a new digest.
    #[must_use]
    pub const fn new(digest: [u8; LENGTH_BYTES]) -> Self {
        Self(digest)
    }

    /// Returns a byte slice of the digest's contents.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Consumes the digest, returning the digest bytes.
    #[must_use]
    pub fn into_inner(self) -> [u8; LENGTH_BYTES] {
        let Self(inner) = self;
        inner
    }

    /// Returns a string in the lowercase hexadecimal representation.
    ///
    /// # Example
    ///
    /// ```rust
    /// use chksum_hash_md5 as md5;
    ///
    /// #[rustfmt::skip]
    /// let digest = [
    ///     0xD4, 0x1D, 0x8C, 0xD9,
    ///     0x8F, 0x00, 0xB2, 0x04,
    ///     0xE9, 0x80, 0x09, 0x98,
    ///     0xEC, 0xF8, 0x42, 0x7E,
    /// ];
    /// let digest = md5::Digest::new(digest);
    /// assert_eq!(
    ///     digest.to_hex_lowercase(),
    ///     "d41d8cd98f00b204e9800998ecf8427e"
    /// );
    /// ```
    #[must_use]
    pub fn to_hex_lowercase(&self) -> String {
        format!("{self:x}")
    }

    /// Returns a string in the uppercase hexadecimal representation.
    ///
    /// # Example
    ///
    /// ```rust
    /// use chksum_hash_md5 as md5;
    ///
    /// #[rustfmt::skip]
    /// let digest = [
    ///     0xD4, 0x1D, 0x8C, 0xD9,
    ///     0x8F, 0x00, 0xB2, 0x04,
    ///     0xE9, 0x80, 0x09, 0x98,
    ///     0xEC, 0xF8, 0x42, 0x7E,
    /// ];
    /// let digest = md5::Digest::new(digest);
    /// assert_eq!(
    ///     digest.to_hex_uppercase(),
    ///     "D41D8CD98F00B204E9800998ECF8427E"
    /// );
    /// ```
    #[must_use]
    pub fn to_hex_uppercase(&self) -> String {
        format!("{self:X}")
    }
}

impl core::Digest for Digest {}

impl AsRef<[u8]> for Digest {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl From<[u8; LENGTH_BYTES]> for Digest {
    fn from(digest: [u8; LENGTH_BYTES]) -> Self {
        Self::new(digest)
    }
}

impl From<Digest> for [u8; LENGTH_BYTES] {
    fn from(digest: Digest) -> Self {
        digest.into_inner()
    }
}

impl Display for Digest {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        LowerHex::fmt(self, f)
    }
}

impl LowerHex for Digest {
    #[rustfmt::skip]
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        let digest = format!(
            "{:02x}{:02x}{:02x}{:02x}\
             {:02x}{:02x}{:02x}{:02x}\
             {:02x}{:02x}{:02x}{:02x}\
             {:02x}{:02x}{:02x}{:02x}",
            self.0[0x0], self.0[0x1], self.0[0x2], self.0[0x3],
            self.0[0x4], self.0[0x5], self.0[0x6], self.0[0x7],
            self.0[0x8], self.0[0x9], self.0[0xA], self.0[0xB],
            self.0[0xC], self.0[0xD], self.0[0xE], self.0[0xF],
        );
        if formatter.alternate() {
            formatter.pad_integral(true, "0x", &digest)
        } else {
            formatter.pad(&digest)
        }
    }
}

impl UpperHex for Digest {
    #[rustfmt::skip]
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        let digest = format!(
            "{:02X}{:02X}{:02X}{:02X}\
             {:02X}{:02X}{:02X}{:02X}\
             {:02X}{:02X}{:02X}{:02X}\
             {:02X}{:02X}{:02X}{:02X}",
            self.0[0x0], self.0[0x1], self.0[0x2], self.0[0x3],
            self.0[0x4], self.0[0x5], self.0[0x6], self.0[0x7],
            self.0[0x8], self.0[0x9], self.0[0xA], self.0[0xB],
            self.0[0xC], self.0[0xD], self.0[0xE], self.0[0xF],
        );
        if formatter.alternate() {
            formatter.pad_integral(true, "0X", &digest)
        } else {
            formatter.pad(&digest)
        }
    }
}

impl TryFrom<&str> for Digest {
    type Error = FormatError;

    fn try_from(digest: &str) -> Result<Self, Self::Error> {
        if digest.len() != LENGTH_HEX {
            let error = Self::Error::InvalidLength {
                value: digest.len(),
                proper: LENGTH_HEX,
            };
            return Err(error);
        }
        let digest = [
            u32::from_str_radix(&digest[0x00..0x08], 16)?.swap_bytes().to_le_bytes(),
            u32::from_str_radix(&digest[0x08..0x10], 16)?.swap_bytes().to_le_bytes(),
            u32::from_str_radix(&digest[0x10..0x18], 16)?.swap_bytes().to_le_bytes(),
            u32::from_str_radix(&digest[0x18..0x20], 16)?.swap_bytes().to_le_bytes(),
        ];
        #[rustfmt::skip]
        let digest = [
            digest[0][0], digest[0][1], digest[0][2], digest[0][3],
            digest[1][0], digest[1][1], digest[1][2], digest[1][3],
            digest[2][0], digest[2][1], digest[2][2], digest[2][3],
            digest[3][0], digest[3][1], digest[3][2], digest[3][3],
        ];
        let digest = Self::from(digest);
        Ok(digest)
    }
}

/// An error type for the digest conversion.
#[derive(Debug, Eq, PartialEq, thiserror::Error)]
pub enum FormatError {
    /// Represents an invalid length error with detailed information.
    #[error("Invalid length `{value}`, proper value `{proper}`")]
    InvalidLength { value: usize, proper: usize },
    /// Represents an error that occurs during parsing.
    #[error(transparent)]
    ParseError(#[from] ParseIntError),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn as_bytes() {
        #[rustfmt::skip]
        let digest = [
            0xD4, 0x1D, 0x8C, 0xD9,
            0x8F, 0x00, 0xB2, 0x04,
            0xE9, 0x80, 0x09, 0x98,
            0xEC, 0xF8, 0x42, 0x7E,
        ];
        assert_eq!(Digest::new(digest).as_bytes(), &digest);
    }

    #[test]
    fn as_ref() {
        #[rustfmt::skip]
        let digest = [
            0xD4, 0x1D, 0x8C, 0xD9,
            0x8F, 0x00, 0xB2, 0x04,
            0xE9, 0x80, 0x09, 0x98,
            0xEC, 0xF8, 0x42, 0x7E,
        ];
        assert_eq!(Digest::new(digest).as_ref(), &digest);
    }

    #[test]
    fn format() {
        #[rustfmt::skip]
        let digest = Digest::new([
            0xD4, 0x1D, 0x8C, 0xD9,
            0x8F, 0x00, 0xB2, 0x04,
            0xE9, 0x80, 0x09, 0x98,
            0xEC, 0xF8, 0x42, 0x7E,
        ]);
        assert_eq!(format!("{digest:x}"), "d41d8cd98f00b204e9800998ecf8427e");
        assert_eq!(format!("{digest:#x}"), "0xd41d8cd98f00b204e9800998ecf8427e");
        assert_eq!(format!("{digest:40x}"), "d41d8cd98f00b204e9800998ecf8427e        ");
        assert_eq!(format!("{digest:>40x}"), "        d41d8cd98f00b204e9800998ecf8427e");
        assert_eq!(format!("{digest:^40x}"), "    d41d8cd98f00b204e9800998ecf8427e    ");
        assert_eq!(format!("{digest:<40x}"), "d41d8cd98f00b204e9800998ecf8427e        ");
        assert_eq!(format!("{digest:.^40x}"), "....d41d8cd98f00b204e9800998ecf8427e....");
        assert_eq!(format!("{digest:.8x}"), "d41d8cd9");
        assert_eq!(format!("{digest:X}"), "D41D8CD98F00B204E9800998ECF8427E");
        assert_eq!(format!("{digest:#X}"), "0XD41D8CD98F00B204E9800998ECF8427E");
        assert_eq!(format!("{digest:40X}"), "D41D8CD98F00B204E9800998ECF8427E        ");
        assert_eq!(format!("{digest:>40X}"), "        D41D8CD98F00B204E9800998ECF8427E");
        assert_eq!(format!("{digest:^40X}"), "    D41D8CD98F00B204E9800998ECF8427E    ");
        assert_eq!(format!("{digest:<40X}"), "D41D8CD98F00B204E9800998ECF8427E        ");
        assert_eq!(format!("{digest:.^40X}"), "....D41D8CD98F00B204E9800998ECF8427E....");
        assert_eq!(format!("{digest:.8X}"), "D41D8CD9");
    }

    #[test]
    fn from() {
        #[rustfmt::skip]
        let digest = [
            0xD4, 0x1D, 0x8C, 0xD9,
            0x8F, 0x00, 0xB2, 0x04,
            0xE9, 0x80, 0x09, 0x98,
            0xEC, 0xF8, 0x42, 0x7E,
        ];
        assert_eq!(Digest::from(digest), Digest::new(digest));
        assert_eq!(<[u8; 16]>::from(Digest::new(digest)), digest);
    }

    #[test]
    fn to_hex() {
        #[rustfmt::skip]
        let digest = Digest::new([
            0xD4, 0x1D, 0x8C, 0xD9,
            0x8F, 0x00, 0xB2, 0x04,
            0xE9, 0x80, 0x09, 0x98,
            0xEC, 0xF8, 0x42, 0x7E,
        ]);
        assert_eq!(digest.to_hex_lowercase(), "d41d8cd98f00b204e9800998ecf8427e");
        assert_eq!(digest.to_hex_uppercase(), "D41D8CD98F00B204E9800998ECF8427E");
    }

    #[test]
    fn try_from() {
        assert_eq!(
            Digest::try_from("d41d8cd98f00b204e9800998ecf8427e"),
            Digest::try_from("D41D8CD98F00B204E9800998ECF8427E")
        );
        #[rustfmt::skip]
        assert_eq!(
            Digest::try_from("D41D8CD98F00B204E9800998ECF8427E"),
            Ok(Digest::new([
                0xD4, 0x1D, 0x8C, 0xD9,
                0x8F, 0x00, 0xB2, 0x04,
                0xE9, 0x80, 0x09, 0x98,
                0xEC, 0xF8, 0x42, 0x7E,
            ]))
        );
        assert!(matches!(Digest::try_from("D4"), Err(FormatError::InvalidLength { .. })));
        assert!(matches!(
            Digest::try_from("D41D8CD98F00B204E9800998ECF8427EXX"),
            Err(FormatError::InvalidLength { .. })
        ));
        assert!(matches!(
            Digest::try_from("D41D8CD98F00B204E9800998ECF842XX"),
            Err(FormatError::ParseError(_))
        ));
    }
}
