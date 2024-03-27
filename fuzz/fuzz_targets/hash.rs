#![no_main]

use chksum_hash_md5 as md5;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    md5::hash(data);
});
