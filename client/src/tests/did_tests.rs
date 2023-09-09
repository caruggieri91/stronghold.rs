// Copyright 2020-2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crypto::ciphers::aes_kw::AesKeyWrap;

use crate::{
    procedures::{
        BIP39Generate,
        DeriveSecret, Ed25519Sign, GenerateKey, GenerateSecret, KeyType,
        MnemonicLanguage, PublicKey, Slip10Derive, Slip10DeriveInput, Slip10Generate, StrongholdProcedure,
        X25519DiffieHellman, DidKeyDeriveInput, DidKeyDerive
    },
    tests::fresh,
    Client, Location, Stronghold,
    tests::did_locations
};

use crypto::{
    ciphers::{aes_gcm::Aes256Gcm, chacha::XChaCha20Poly1305},
    keys::slip10::ChainCode,
    signatures::ed25519,
};
use stronghold_utils::random;

// Did Key Derive for Polito - TESTS

#[tokio::test]
async fn usecase_did_key_derive_keys() -> Result<(), Box<dyn std::error::Error>> {
    // Generate a BIP39 seed or retrieve from Location
    let stronghold: Stronghold = Stronghold::default();
    let client: Client = stronghold.create_client(b"client_path").unwrap();

    let passphrase = random::string(4096);
    let seed = fresh::location();

    let generate_bip39 = BIP39Generate {
        language: MnemonicLanguage::English,
        passphrase: Some(passphrase.clone()),
        output: seed.clone(),
    };

    let generate_bip39_result = client.execute_procedure(generate_bip39);
    assert!(generate_bip39_result.is_ok());

    if generate_bip39_result.is_ok() {
        println!("Mnemonic: {}", generate_bip39_result.ok().unwrap());
    }

    let did_key_derive: DidKeyDerive = DidKeyDerive {
        input: DidKeyDeriveInput::Seed(seed.clone()),
        registry: 1,
        method_type: 1,
        contract_addr: "0x24a0ca094f13fe1376f8f79e58a7b192da5a7e01".to_string(),
        verification_method: 1,
        index: 0,
        output: fresh::location(),
    };

    let did_key_derive_result = client.execute_procedure(did_key_derive);
    assert!(did_key_derive_result.is_ok());

    if did_key_derive_result.is_ok() {
        println!("Chain Code:");
        println!("{:x?}", did_key_derive_result.ok().unwrap());
    }

    Ok(())
}

#[tokio::test]
async fn usecase_sign_with_did_key_derive() -> Result<(), Box<dyn std::error::Error>> {
    let stronghold: Stronghold = Stronghold::default();
    let client: Client = stronghold.create_client(b"client_path").unwrap();

    let vault_path = random::variable_bytestring(1024);
    // Seed vault location
    let seed = Location::generic(vault_path.clone(), random::variable_bytestring(1024));
    // Key from DidKeyDerive location into vault
    let key = Location::generic(vault_path, random::variable_bytestring(1024));

    let passphrase = random::string(1024);
    let generate_bip39 = BIP39Generate {
        language: MnemonicLanguage::English,
        passphrase: Some(passphrase.clone()),
        output: seed.clone(),
    };

    assert!(client.execute_procedure(generate_bip39).is_ok());

    let did_key_derive: DidKeyDerive = DidKeyDerive {
        input: DidKeyDeriveInput::Seed(seed.clone()),
        registry: 1,
        method_type: 1,
        contract_addr: "0x24a0ca094f13fe1376f8f79e58a7b192da5a7e01".to_string(),
        verification_method: 1,
        index: 0,
        output: key.clone(),
    };

    assert!(client.execute_procedure(did_key_derive).is_ok());

    let ed25519_pk = PublicKey {
        private_key: key.clone(),
        ty: KeyType::Ed25519,
    };
    let pk: [u8; ed25519::PUBLIC_KEY_LENGTH] = client.execute_procedure(ed25519_pk).unwrap();

    let msg = fresh::variable_bytestring(4096);

    let ed25519_sign = Ed25519Sign {
        private_key: key,
        msg: msg.clone(),
    };
    let sig: [u8; ed25519::SIGNATURE_LENGTH] = client.execute_procedure(ed25519_sign).unwrap();

    let pk = ed25519::PublicKey::try_from_bytes(pk).unwrap();
    let sig = ed25519::Signature::from_bytes(sig);
    assert!(pk.verify(&sig, &msg));

    Ok(())
}

#[tokio::test]
async fn usecase_multiple_did_keys_for_multiple_accounts() -> Result<(), Box<dyn std::error::Error>> {
    let stronghold: Stronghold = Stronghold::default();
    let client: Client = stronghold.create_client(b"client_path").unwrap();

    // Vault path 
    let vault_path = did_locations::generate_vault_path();
    // Seed vault location
    let seed = Location::generic(vault_path.clone(), random::variable_bytestring(1024));

    // Seed BIP39 generation
    let passphrase = random::string(1024);
    let generate_bip39 = BIP39Generate {
        language: MnemonicLanguage::English,
        passphrase: Some(passphrase.clone()),
        output: seed.clone(),
    };

    assert!(client.execute_procedure(generate_bip39).is_ok());

    // Key Derive (multiple keys)

    let contract1 = "0x24a0ca094f13fe1376f8f79e58a7b192da5a7e01".to_string();
    let contract2 = "0xbd2228071cba2160e4f18d660e0f27d6862ad783".to_string();

    let verification_method_1: u32 = 1; // Authentication
    let verification_method_2: u32 = 3; // Key agreement

    let index0: u32 = 0;
    let index1: u32 = 1;
    let index2: u32 = 2;

    // for contract 1 derive 4 keys with path m/390/1/1/uint32(contract1)/1/0, m/390/1/1/uint32(contract1)/1/1, 
    // m/390/1/1/uint32(contract1)/1/2 and m/390/1/1/uint32(contract1)/3/0

    // Generating locations to store key
    let location_for_key1_contract1 = did_locations::location_for_key(vault_path.clone(), contract1.clone(), verification_method_1, index0);
    let location_for_key2_contract1 = did_locations::location_for_key(vault_path.clone(), contract1.clone(), verification_method_1, index1);
    let location_for_key3_contract1 = did_locations::location_for_key(vault_path.clone(), contract1.clone(), verification_method_1, index2);
    let location_for_key4_contract1 = did_locations::location_for_key(vault_path.clone(), contract1.clone(), verification_method_2, index0);

    // Procedures
    let did_key1_derive_contract1: DidKeyDerive = DidKeyDerive {
        input: DidKeyDeriveInput::Seed(seed.clone()),
        registry: 1,
        method_type: 1,
        contract_addr: contract1.clone(),
        verification_method: verification_method_1,
        index: index0,
        output: location_for_key1_contract1.clone(),
    };

    assert!(client.execute_procedure(did_key1_derive_contract1).is_ok());

    let did_key2_derive_contract1: DidKeyDerive = DidKeyDerive {
        input: DidKeyDeriveInput::Seed(seed.clone()),
        registry: 1,
        method_type: 1,
        contract_addr: contract1.clone(),
        verification_method: verification_method_1,
        index: index1,
        output: location_for_key2_contract1.clone(),
    };

    assert!(client.execute_procedure(did_key2_derive_contract1).is_ok());

    let did_key3_derive_contract1: DidKeyDerive = DidKeyDerive {
        input: DidKeyDeriveInput::Seed(seed.clone()),
        registry: 1,
        method_type: 1,
        contract_addr: contract1.clone(),
        verification_method: verification_method_1,
        index: index2,
        output: location_for_key3_contract1.clone(),
    };

    assert!(client.execute_procedure(did_key3_derive_contract1).is_ok());

    let did_key4_derive_contract1: DidKeyDerive = DidKeyDerive {
        input: DidKeyDeriveInput::Seed(seed.clone()),
        registry: 1,
        method_type: 1,
        contract_addr: contract1.clone(),
        verification_method: verification_method_2,
        index: index0,
        output: location_for_key4_contract1.clone(),
    };

    assert!(client.execute_procedure(did_key4_derive_contract1).is_ok());

    // for contract 2 derive 3 keys with path m/390/1/1/uint32(contract2)/1/0, m/390/1/1/uint32(contract2)/3/0, 
    // m/390/1/1/uint32(contract2)/3/1

    let location_for_key1_contract2 = did_locations::location_for_key(vault_path.clone(), contract2.clone(), verification_method_1, index0);
    let location_for_key2_contract2 = did_locations::location_for_key(vault_path.clone(), contract2.clone(), verification_method_2, index0);
    let location_for_key3_contract2 = did_locations::location_for_key(vault_path.clone(), contract2.clone(), verification_method_2, index1);

    let did_key1_derive_contract2: DidKeyDerive = DidKeyDerive {
        input: DidKeyDeriveInput::Seed(seed.clone()),
        registry: 1,
        method_type: 1,
        contract_addr: contract2.clone(),
        verification_method: verification_method_1,
        index: index0,
        output: location_for_key1_contract2.clone(),
    };

    let did_key2_derive_contract2: DidKeyDerive = DidKeyDerive {
        input: DidKeyDeriveInput::Seed(seed.clone()),
        registry: 1,
        method_type: 1,
        contract_addr: contract2.clone(),
        verification_method: verification_method_2,
        index: index0,
        output: location_for_key2_contract2.clone(),
    };

    let did_key3_derive_contract2: DidKeyDerive = DidKeyDerive {
        input: DidKeyDeriveInput::Seed(seed.clone()),
        registry: 1,
        method_type: 1,
        contract_addr: contract2.clone(),
        verification_method: verification_method_2,
        index: index1,
        output: location_for_key3_contract2.clone(),
    };

    assert!(client.execute_procedure(did_key1_derive_contract2).is_ok());
    assert!(client.execute_procedure(did_key2_derive_contract2).is_ok());
    assert!(client.execute_procedure(did_key3_derive_contract2).is_ok());

    // Signature

    // Sign for contract1 with key at path m/390/1/1/uint32(contract1)/1/2
    // Generate record_path with utils function
    let record_path = did_locations::generate_record_path(contract1.clone(), 1, 2);
    // Get location
    let loc_key1 = did_locations::location_from_vault_and_record_path(vault_path.clone(), record_path.clone());
    // Sign
    // 1. get public key for key1
    let key1_ed25519_pk = PublicKey {
        private_key: loc_key1.clone(),
        ty: KeyType::Ed25519,
    };
    let pk1: [u8; ed25519::PUBLIC_KEY_LENGTH] = client.execute_procedure(key1_ed25519_pk).unwrap();
    // 2. random msg for key1
    let msg1 = fresh::variable_bytestring(4096);
    // 3. sign with key1
    let key1_ed25519_sign = Ed25519Sign {
        private_key: loc_key1,
        msg: msg1.clone(),
    };
    let sig1: [u8; ed25519::SIGNATURE_LENGTH] = client.execute_procedure(key1_ed25519_sign).unwrap();
    // 4. verifiy signature
    let pk1 = ed25519::PublicKey::try_from_bytes(pk1).unwrap();
    let sig1 = ed25519::Signature::from_bytes(sig1);
    assert!(pk1.verify(&sig1, &msg1));

    // Sign for contract2 with key at path m/390/1/1/uint32(contract2)/1/0
    // Define a record path with 0xbd2228071cba2160e4f18d660e0f27d6862ad783
    let record_path_2: Vec<u8> = vec![0xbd, 0x22, 0x28, 0x07, 0x1c, 0xba, 0x21, 0x60, 0xe4, 0xf1, 0x8d, 0x66, 0x0e, 0x0f, 0x27, 0xd6, 0x86, 0x2a, 0xd7, 0x83,
        0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00];
     // Get location
     let loc_key2 = did_locations::location_from_vault_and_record_path(vault_path.clone(), record_path_2.clone());
    // Sign
    // 1. get public key for key2
    let key2_ed25519_pk = PublicKey {
        private_key: loc_key2.clone(),
        ty: KeyType::Ed25519,
    };
    let pk2: [u8; ed25519::PUBLIC_KEY_LENGTH] = client.execute_procedure(key2_ed25519_pk).unwrap();
    // 2. random msg for key2
    let msg2 = fresh::variable_bytestring(4096);
    // 3. sign with key2
    let key2_ed25519_sign = Ed25519Sign {
        private_key: loc_key2,
        msg: msg2.clone(),
    };
    let sig2: [u8; ed25519::SIGNATURE_LENGTH] = client.execute_procedure(key2_ed25519_sign).unwrap();
    // 4. verifiy signature
    let pk2 = ed25519::PublicKey::try_from_bytes(pk2).unwrap();
    let sig2 = ed25519::Signature::from_bytes(sig2);
    assert!(pk2.verify(&sig2, &msg2));

    // Signature with unexisting key -> must generate error when trying to retrieve public key from an
    // unexisting location

    let rec_path_unexisting = did_locations::generate_record_path(contract1.clone(), 2, 24);
    let loc_unexisting = did_locations::location_from_vault_and_record_path(vault_path.clone(), rec_path_unexisting.clone());

    // Trying to get public key
    let unexisting_key_ed25519_pk = PublicKey {
        private_key: loc_unexisting.clone(),
        ty: KeyType::Ed25519,
    };
    assert!(client.execute_procedure(unexisting_key_ed25519_pk).is_err());

    Ok(())
}