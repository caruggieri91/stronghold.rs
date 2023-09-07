// Copyright 2020-2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::fmt::Write;
pub use stronghold_utils::{random::*, test_utils};

use crate::Location;

/// Generates a random Vault Path and use this as default.
pub fn generate_vault_path() -> Vec<u8> {
    variable_bytestring(4096)
}

/// Generates a [`Location`] using contract_address, verification method and index of the key.
/// The record path is with usize of 28 bytes
pub fn location_for_key(vault_path: Vec<u8>, contract_address: String, verification_method: u32, index: u32) -> Location {
    return Location::generic(vault_path, generate_record_path(contract_address, verification_method, index));
}

/// Generate a record path for [`Location`] using contract_address, verification method and index of the key.
/// For example for address: 0x24a0ca094f13fe1376f8f79e58a7b192da5a7e01, verification_method: 1 and index: 1 a record path in which key is stored is 
/// \[24, A0, CA, 09, 4F, 13, FE, 13, 76, F8, F7, 9E, 58, A7, B1, 92, DA, 5A, 7E, 01, 00, 00, 00, 01, 00, 00, 00, 01\]
pub fn generate_record_path(contract_address: String, verification_method: u32, index: u32) -> Vec<u8>{
    // sanitize contract address
    let sanitized = sanitize_addr(contract_address);

    // convert u32 to vec<u8>
    let mut verification_method_bytes = verification_method.to_be_bytes().to_vec();
    let mut index_bytes = index.to_be_bytes().to_vec();

    // concat all and create a record_path
    let mut record_path = hex::decode(sanitized).unwrap();
    record_path.append(&mut verification_method_bytes);
    record_path.append(&mut index_bytes);
    
    //println!("{:02X?}", record_path);

    return record_path;
}

pub fn location_from_vault_and_record_path(vault_path: Vec<u8>, record_path: Vec<u8>) -> Location {
    Location::Generic { vault_path: vault_path, record_path: record_path }
}

// Remove the 0x from the address string if present
fn sanitize_addr(mut addr: String) -> String {
    if addr.contains("0x") {
        addr = addr.replace("0x", "");
    }

    return addr;
}

