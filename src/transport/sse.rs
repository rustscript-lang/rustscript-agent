//! Incremental, bounded, data-only EventSource framing.
//!
//! This layer has no networking, credentials, JSON or provider semantics. The
//! caller owns raw-body limits, cancellation, deadlines and record decoding.

const BOM: [u8; 3] = [0xEF, 0xBB, 0xBF];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FrameError {
    LineTooLong,
    DataTooLong,
    InvalidUtf8,
}

pub(crate) struct SseFramer {
    max_line_bytes: usize,
    max_data_bytes: usize,
    prefix: Vec<u8>,
    bom_decided: bool,
    after_cr: bool,
    line: Vec<u8>,
    data: Vec<u8>,
    has_data: bool,
}

impl SseFramer {
    pub(crate) fn new(max_line_bytes: usize, max_data_bytes: usize) -> Self {
        Self {
            max_line_bytes,
            max_data_bytes,
            prefix: Vec::new(),
            bom_decided: false,
            after_cr: false,
            line: Vec::new(),
            data: Vec::new(),
            has_data: false,
        }
    }

    /// Returns one complete data item only after its terminating blank line.
    pub(crate) fn push_byte(&mut self, byte: u8) -> Result<Option<Vec<u8>>, FrameError> {
        if !self.bom_decided {
            self.prefix.push(byte);
            if self.prefix == BOM {
                self.prefix.clear();
                self.bom_decided = true;
                return Ok(None);
            }
            if BOM.starts_with(&self.prefix) {
                return Ok(None);
            }
            let pending = std::mem::take(&mut self.prefix);
            self.bom_decided = true;
            for byte in pending {
                if let Some(record) = self.process_byte(byte)? {
                    return Ok(Some(record));
                }
            }
            return Ok(None);
        }
        self.process_byte(byte)
    }

    fn process_byte(&mut self, byte: u8) -> Result<Option<Vec<u8>>, FrameError> {
        if self.after_cr {
            self.after_cr = false;
            if byte == b'\n' {
                return Ok(None);
            }
        }
        match byte {
            b'\r' => {
                self.after_cr = true;
                self.process_line()
            }
            b'\n' => self.process_line(),
            _ => {
                if self.line.len() >= self.max_line_bytes {
                    return Err(FrameError::LineTooLong);
                }
                self.line.push(byte);
                Ok(None)
            }
        }
    }

    fn process_line(&mut self) -> Result<Option<Vec<u8>>, FrameError> {
        let line = std::mem::take(&mut self.line);
        let text = std::str::from_utf8(&line).map_err(|_| FrameError::InvalidUtf8)?;
        if text.is_empty() {
            if self.has_data {
                self.has_data = false;
                return Ok(Some(std::mem::take(&mut self.data)));
            }
            return Ok(None);
        }
        if text.starts_with(':') {
            return Ok(None);
        }
        let (field, value) = text.split_once(':').unwrap_or((text, ""));
        let value = value.strip_prefix(' ').unwrap_or(value);
        if field == "data" {
            let added = value.len() + usize::from(self.has_data);
            self.data
                .len()
                .checked_add(added)
                .filter(|total| *total <= self.max_data_bytes)
                .ok_or(FrameError::DataTooLong)?;
            if self.has_data {
                self.data.push(b'\n');
            }
            self.data.extend_from_slice(value.as_bytes());
            self.has_data = true;
        }
        Ok(None)
    }

    /// EOF and caller cancellation discard an unterminated item without dispatch.
    pub(crate) fn discard_pending(&mut self) {
        self.prefix.clear();
        self.line.clear();
        self.data.clear();
        self.has_data = false;
    }
}

#[cfg(test)]
mod tests {
    use super::{BOM, FrameError, SseFramer};

    fn collect(framer: &mut SseFramer, bytes: &[u8]) -> Result<Vec<Vec<u8>>, FrameError> {
        let mut records = Vec::new();
        for byte in bytes {
            if let Some(record) = framer.push_byte(*byte)? {
                records.push(record);
            }
        }
        Ok(records)
    }

    #[test]
    fn multiline_data_and_metadata_are_framed_without_interpretation() {
        let mut framer = SseFramer::new(128, 128);
        let records = collect(
            &mut framer,
            b":comment\nevent: custom\nid: 7\nretry: 1\ndata: one\ndata:two\n\ndata: three\n\n",
        )
        .unwrap();
        assert_eq!(records, vec![b"one\ntwo".to_vec(), b"three".to_vec()]);
    }
    #[test]
    fn bom_crlf_and_split_utf8_preserve_data() {
        let mut framer = SseFramer::new(128, 128);
        let mut bytes = BOM.to_vec();
        bytes.extend_from_slice("data: 日本語\r\n\r\n".as_bytes());
        assert_eq!(
            collect(&mut framer, &bytes).unwrap(),
            vec!["日本語".as_bytes().to_vec()]
        );
    }
    #[test]
    fn empty_data_is_a_record_and_empty_lines_alone_are_not() {
        let mut framer = SseFramer::new(32, 32);
        assert_eq!(
            collect(&mut framer, b"\n\ndata:\n\n").unwrap(),
            vec![Vec::<u8>::new()]
        );
    }
    #[test]
    fn line_limit_is_in_bytes_and_applies_to_control_lines() {
        let mut framer = SseFramer::new(4, 128);
        assert_eq!(collect(&mut framer, b"event"), Err(FrameError::LineTooLong));
    }
    #[test]
    fn data_limit_counts_inserted_newlines() {
        let mut framer = SseFramer::new(32, 2);
        assert_eq!(
            collect(&mut framer, b"data:a\ndata:b\n\n"),
            Err(FrameError::DataTooLong)
        );
    }
    #[test]
    fn invalid_utf8_is_rejected_at_line_completion() {
        let mut framer = SseFramer::new(32, 32);
        assert_eq!(
            collect(&mut framer, b"data:\xff\n"),
            Err(FrameError::InvalidUtf8)
        );
    }
    #[test]
    fn partial_items_are_discarded_at_eof() {
        let mut framer = SseFramer::new(32, 32);
        assert!(collect(&mut framer, b"data: partial\n").unwrap().is_empty());
        framer.discard_pending();
        assert_eq!(
            collect(&mut framer, b"data: next\n\n").unwrap(),
            vec![b"next".to_vec()]
        );
    }
}
