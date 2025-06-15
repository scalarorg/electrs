use super::codec::NodeCodec;
use parity_scale_codec as codec;

/// Error type used for trie related errors.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Error<H> {
    BadFormat,
    Decode(codec::Error),
    InvalidRecording(Vec<u8>, bool),
    TrieError(Box<trie_db::TrieError<H, Self>>),
}

impl<H> core::fmt::Display for Error<H> {
    fn fmt(&self, fmt: &mut core::fmt::Formatter) -> core::fmt::Result {
        fmt.write_str("Error")
    }
}

impl<H> std::error::Error for Error<H> where H: core::fmt::Debug {}

impl<H> From<codec::Error> for Error<H> {
    fn from(x: codec::Error) -> Self {
        Error::Decode(x)
    }
}

impl<H> From<Box<trie_db::TrieError<H, Self>>> for Error<H> {
    fn from(x: Box<trie_db::TrieError<H, Self>>) -> Self {
        Error::TrieError(x)
    }
}

pub struct KeccakTrieLayout;

impl trie_db::TrieLayout for KeccakTrieLayout {
    type Hash = keccak_hasher::KeccakHasher;
    type Codec = NodeCodec<Self::Hash>;

    const USE_EXTENSION: bool = true;
    const MAX_INLINE_VALUE: Option<u32> = None;
}
