//! Interop helper for `interop/run.sh`.
//!
//! keys                  -> a=, b=, A=, A_a= lines: two shares, the lock key
//!                          (a+b)G and the share key aG
//! sign <a> <b> <file>   -> joint-key signature over the bytes of <file>
//! All values are hex; scalars are little-endian.

use std::{env, fs};
use swap_nexus::{joint_public_key, JointKey, KeyShare};

fn share(hex_str: &str) -> KeyShare {
    let bytes: [u8; 32] = hex::decode(hex_str).unwrap().try_into().unwrap();
    KeyShare::from_bytes(bytes).expect("share must be nonzero and below 2^252")
}

fn main() {
    let args: Vec<String> = env::args().collect();
    match args[1].as_str() {
        "keys" => {
            let (a, b) = (KeyShare::random(), KeyShare::random());
            println!("a={}", hex::encode(a.to_bytes()));
            println!("b={}", hex::encode(b.to_bytes()));
            println!(
                "A={}",
                hex::encode(joint_public_key(&a.public(), &b.public()).unwrap())
            );
            println!("A_a={}", hex::encode(a.public().compress().to_bytes()));
        }
        "sign" => {
            let message = fs::read(&args[4]).unwrap();
            let joint = JointKey::from_shares(&share(&args[2]), &share(&args[3]));
            println!("{}", hex::encode(joint.sign(&message)));
        }
        _ => panic!("usage: jointkey keys | sign <a> <b> <file>"),
    }
}
