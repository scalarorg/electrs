use sha2::{Digest, Sha256};

// fn double_sha256(data: &[u8]) -> Vec<u8> {
//     let first = Sha256::digest(data);
//     let second = Sha256::digest(&first);
//     second.to_vec()
// }

// fn merkle_root(mut txids: Vec<String>) -> String {
//     let mut hashes: Vec<Vec<u8>> = txids
//         .iter()
//         .map(|hex| hex::decode(hex).unwrap().into_iter().rev().collect()) // little-endian
//         .collect();

//     while hashes.len() > 1 {
//         if hashes.len() % 2 == 1 {
//             hashes.push(hashes.last().unwrap().clone());
//         }

//         hashes = hashes
//             .chunks(2)
//             .map(|pair| double_sha256(&[&pair[0], &pair[1]].concat()))
//             .collect();
//     }

//     hex::encode(hashes[0].iter().rev().cloned().collect::<Vec<u8>>()) // convert back to big-endian hex
// }

// fn main() {
//     let txids = vec![
//         "b0f8f25cf07b25b1b95f4c3f83e21b1665e3a2026e84312e4f4b0b2488c032b9".to_string(),
//         "1a6c9a6a33455d0f7ff875fc6c2b8814e7c3a17d2cf88bc59aaf4e2b1bbf8379".to_string(),
//         // Add more TXIDs here...
//     ];

//     let root = merkle_root(txids);
//     println!("Merkle Root: {}", root);
// }
