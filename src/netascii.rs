use crate::errors::TFTPError;
use anyhow::anyhow;
use std::string::String;

const NL: u8 = 0x0A;
const CR: u8 = 0x0D;

/// Encodes some bytes into a "netascii" String.
pub fn encode<T: AsRef<[u8]>>(input: T) -> Result<String, TFTPError> {
    // Verify that all characters are within printable ASCII + some other characters.
    if !verify_bytes(&input) {
        return Err(TFTPError::NetASCIIError(anyhow!(
            "characters are out of ASCII range"
        )));
    }

    // Encode newlines.
    let encoded_bytes = encode_newlines(input);
    String::from_utf8(encoded_bytes).map_err(|e| TFTPError::NetASCIIError(e.into()))
}

pub fn decode<T: AsRef<[u8]>>(input: T) -> Result<String, TFTPError> {
    // Verify that all characters are within printable ASCII + some other characters.
    if !verify_bytes(&input) {
        return Err(TFTPError::NetASCIIError(anyhow!(
            "characters are out of ASCII range"
        )));
    }

    // Decode newlines (if needed).
    let decoded_bytes = decode_newlines(input);
    let s = String::from_utf8(decoded_bytes).map_err(|e| TFTPError::NetASCIIError(e.into()))?;
    Ok(s)
}

pub struct NetASCIIEncode<I>
where
    I: Iterator<Item = u8>,
{
    iter: I,
    last_was_cr: bool,
    pending_nl: bool,
}

impl<I> Iterator for NetASCIIEncode<I>
where
    I: Iterator<Item = u8>,
    I::Item: Copy,
{
    type Item = I::Item;

    fn next(&mut self) -> Option<Self::Item> {
        if self.pending_nl {
            self.pending_nl = false;
            return Some(NL);
        }

        match self.iter.next() {
            None => None,
            Some(v) => match v {
                CR => {
                    self.last_was_cr = true;
                    Some(v)
                }
                NL => {
                    if !self.last_was_cr {
                        self.last_was_cr = false;
                        self.pending_nl = true;
                        Some(CR)
                    } else {
                        Some(NL)
                    }
                }
                _ => {
                    self.last_was_cr = false;
                    Some(v)
                }
            },
        }
    }
}

impl<I> NetASCIIEncode<I>
where
    I: Iterator<Item = u8>,
{
    fn new(iter: I) -> Self {
        NetASCIIEncode {
            iter,
            last_was_cr: false,
            pending_nl: false,
        }
    }
}

pub trait NetASCIIEncodeAdapter
where
    Self: Sized + Iterator<Item = u8>,
{
    fn netascii_encode(self) -> NetASCIIEncode<Self>;
}

impl<I> NetASCIIEncodeAdapter for I
where
    I: Iterator<Item = u8>,
{
    fn netascii_encode(self) -> NetASCIIEncode<Self> {
        NetASCIIEncode::new(self)
    }
}

pub struct NetASCIIDecode<I>
where
    I: Iterator<Item = u8>,
{
    iter: std::iter::Peekable<I>,
}

impl<I> Iterator for NetASCIIDecode<I>
where
    I: Iterator<Item = u8>,
{
    type Item = I::Item;

    fn next(&mut self) -> Option<Self::Item> {
        match self.iter.next() {
            None => None,
            Some(cur) => match cur {
                CR => match self.iter.peek() {
                    Some(next) if *next == NL => {
                        self.iter.next();
                        Some(NL)
                    }
                    _ => Some(cur),
                },
                _ => Some(cur),
            },
        }
    }
}

impl<I> NetASCIIDecode<I>
where
    I: Iterator<Item = u8>,
{
    fn new(iter: I) -> Self {
        NetASCIIDecode {
            iter: iter.peekable(),
        }
    }
}

pub trait NetASCIIDecodeAdapter
where
    Self: Sized + Iterator<Item = u8>,
{
    fn netascii_decode(self) -> NetASCIIDecode<Self>;
}

impl<I> NetASCIIDecodeAdapter for I
where
    I: Iterator<Item = u8>,
{
    fn netascii_decode(self) -> NetASCIIDecode<Self> {
        NetASCIIDecode::new(self)
    }
}

/// Returns true if all the bytes are valid "netascii" characters.
fn verify_bytes<T: AsRef<[u8]>>(input: T) -> bool {
    for x in input.as_ref() {
        if (*x < 0x20 || *x > 0x7F)
            && *x != 0x00
            && *x != 0x07
            && *x != 0x08
            && *x != 0x09
            && *x != NL
            && *x != 0x0B
            && *x != 0x0C
            && *x != CR
        {
            return false;
        }
    }
    true
}

/// Prefixes all "\n" with "\r", unless they're already prefixed with "\r". So "\n" becomes "\r\n".
fn encode_newlines<T: AsRef<[u8]>>(input: T) -> Vec<u8> {
    input.as_ref().iter().copied().netascii_encode().collect()
}

/// Replaces "\r\n" with "\n" unless you're on a system that likes "\r\n" (windows).
#[cfg(not(target_os = "windows"))]
fn decode_newlines<T: AsRef<[u8]>>(input: T) -> Vec<u8> {
    decode_newlines_real(input: T)
}

/// Replaces "\r\n" with "\n" unless you're on a system that likes "\r\n" (windows).
#[cfg(target_os = "windows")]
fn decode_newlines<T: AsRef<[u8]>>(input: T) -> Vec<u8> {
    input.as_ref().to_vec()
}

#[cfg(any(not(target_os = "windows"), test))]
fn decode_newlines_real<T: AsRef<[u8]>>(input: T) -> Vec<u8> {

    input.as_ref().iter().copied().netascii_decode().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_newlines_empty() {
        let input: Vec<u8> = vec![];
        let want: Vec<u8> = vec![];
        assert_eq!(encode_newlines(input), want);
    }

    #[test]
    fn test_encode_newlines_basic() {
        // 'AHOY'
        let input: Vec<u8> = vec![65, 72, 79, 89];
        let want: Vec<u8> = vec![65, 72, 79, 89];
        assert_eq!(encode_newlines(input), want);
    }

    #[test]
    fn test_encode_newlines_single_cr() {
        // 'AHOY\rTHERE'
        let input: Vec<u8> = vec![65, 72, 79, 89, CR, 84, 72, 69, 82, 69];
        let want: Vec<u8> = vec![65, 72, 79, 89, CR, 84, 72, 69, 82, 69];
        assert_eq!(encode_newlines(input), want);
    }

    #[test]
    fn test_encode_newlines_single_nl() {
        // 'AHOY\nTHERE'
        let input: Vec<u8> = vec![65, 72, 79, 89, NL, 84, 72, 69, 82, 69];

        // 'AHOY\r\nTHERE'
        let want: Vec<u8> = vec![65, 72, 79, 89, CR, NL, 84, 72, 69, 82, 69];
        assert_eq!(encode_newlines(input), want);
    }

    #[test]
    fn test_encode_newlines_crnl() {
        // 'AHOY\r\nTHERE'
        let input: Vec<u8> = vec![65, 72, 79, 89, CR, NL, 84, 72, 69, 82, 69];

        // 'AHOY\r\nTHERE'
        let want: Vec<u8> = vec![65, 72, 79, 89, CR, NL, 84, 72, 69, 82, 69];
        assert_eq!(encode_newlines(input), want);
    }

    #[test]
    fn test_encode_newlines_many_nl() {
        // '\n\n\n\n\n'
        let input: Vec<u8> = vec![NL, NL, NL, NL, NL];

        // '\r\n\r\n\r\n\r\n\r\n'
        let want: Vec<u8> = vec![CR, NL, CR, NL, CR, NL, CR, NL, CR, NL];
        assert_eq!(encode_newlines(input), want);
    }

    #[test]
    fn test_encode_newlines_many_nl_sandwich() {
        // 'AHOY\n\n\n\n\nTHERE'
        let input: Vec<u8> = vec![65, 72, 79, 89, NL, NL, NL, NL, NL, 84, 72, 69, 82, 69];

        // 'AHOY\r\n\r\n\r\n\r\n\r\nTHERE'
        let want: Vec<u8> = vec![
            65, 72, 79, 89, CR, NL, CR, NL, CR, NL, CR, NL, CR, NL, 84, 72, 69, 82, 69,
        ];
        assert_eq!(encode_newlines(input), want);
    }

    #[test]
    fn test_decode_newlines_many_nl_sandwich() {
        // 'AHOY\r\n\r\n\r\n\r\n\r\nTHERE'
        let input: Vec<u8> = vec![
            65, 72, 79, 89, CR, NL, CR, NL, CR, NL, CR, NL, CR, NL, 84, 72, 69, 82, 69,
        ];

        // 'AHOY\n\n\n\n\nTHERE'
        let want: Vec<u8> = vec![65, 72, 79, 89, NL, NL, NL, NL, NL, 84, 72, 69, 82, 69];
        assert_eq!(decode_newlines_real(input), want);
    }

    #[test]
    fn test_decode_newlines_real_empty() {
        let input: Vec<u8> = vec![];
        let want: Vec<u8> = vec![];
        assert_eq!(decode_newlines_real(input), want);
    }

    #[test]
    fn test_decode_newlines_real_one() {
        let input: Vec<u8> = vec![5];
        let want: Vec<u8> = vec![5];
        assert_eq!(decode_newlines_real(input), want);
    }

    #[test]
    fn test_decode_newlines_real_two() {
        let input: Vec<u8> = vec![5, 6];
        let want: Vec<u8> = vec![5, 6];
        assert_eq!(decode_newlines_real(input), want);
    }

    #[test]
    fn test_decode_newlines_real_three() {
        let input: Vec<u8> = vec![5, 6, 7];
        let want: Vec<u8> = vec![5, 6, 7];
        assert_eq!(decode_newlines_real(input), want);
    }

    #[test]
    fn test_decode_newlines_real_two_replace() {
        let input: Vec<u8> = vec![CR, NL];
        let want: Vec<u8> = vec![NL];
        assert_eq!(decode_newlines_real(input), want);
    }

    #[test]
    fn test_decode_newlines_real_three_replace() {
        let input: Vec<u8> = vec![CR, NL, CR];
        let want: Vec<u8> = vec![NL, CR];
        assert_eq!(decode_newlines_real(input), want);
    }

    #[test]
    fn test_decode_newlines_real_sneaky() {
        let input: Vec<u8> = vec![CR, CR, NL, NL];
        let want: Vec<u8> = vec![CR, NL, NL];
        assert_eq!(decode_newlines_real(input), want);
    }

    #[test]
    fn test_decode_newlines_real_sandwich() {
        let input: Vec<u8> = vec![
            65, 72, 79, 89, CR, NL, CR, NL, CR, NL, CR, NL, CR, NL, 84, 72, 69, 82, 69,
        ];
        let want: Vec<u8> = vec![65, 72, 79, 89, NL, NL, NL, NL, NL, 84, 72, 69, 82, 69];
        assert_eq!(decode_newlines_real(input), want);
    }

    #[test]
    fn test_encode_within_range() {
        let input = String::from("Hello - is it me you're looking for?\r\n\0\t");
        assert!(matches!(encode(input), Ok(_)));
    }

    #[test]
    fn test_encode_outside_range() {
        let input = vec![0xff];
        assert!(matches!(encode(input), Err(TFTPError::NetASCIIError(_))));
    }
}
