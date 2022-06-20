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
    let s = String::from_utf8(encoded_bytes).map_err(|e| TFTPError::NetASCIIError(e.into()))?;
    Ok(s)
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
    let mut result = vec![];
    let input_ref = input.as_ref();

    let mut first = true;
    for i in 0..input_ref.len() {
        if (first || input_ref[i - 1] != CR) && input_ref[i] == NL {
            result.push(CR)
        }
        first = false;
        result.push(input_ref[i]);
    }

    result
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
    let mut result = Vec::with_capacity(input.as_ref().len());

    let input_ref = input.as_ref();

    let mut i = 0;
    while i < input_ref.len() {
        result.push(input_ref[i]);
        if i + 1 < input_ref.len() && input_ref[i] == CR && input_ref[i + 1] == NL {
            i += 2;
            continue;
        }
        i += 1;
    }

    result
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
        let want: Vec<u8> = vec![CR];
        assert_eq!(decode_newlines_real(input), want);
    }

    #[test]
    fn test_decode_newlines_real_three_replace() {
        let input: Vec<u8> = vec![CR, NL, CR];
        let want: Vec<u8> = vec![CR, CR];
        assert_eq!(decode_newlines_real(input), want);
    }

    #[test]
    fn test_decode_newlines_real_sneaky() {
        let input: Vec<u8> = vec![CR, CR, NL, NL];
        let want: Vec<u8> = vec![CR, CR, NL];
        assert_eq!(decode_newlines_real(input), want);
    }

    #[test]
    fn test_decode_newlines_real_sandwich() {
        let input: Vec<u8> = vec![
            65, 72, 79, 89, CR, NL, CR, NL, CR, NL, CR, NL, CR, NL, 84, 72, 69, 82, 69,
        ];
        let want: Vec<u8> = vec![65, 72, 79, 89, CR, CR, CR, CR, CR, 84, 72, 69, 82, 69];
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
