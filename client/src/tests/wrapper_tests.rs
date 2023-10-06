use crate::procedures::{SeedGeneratorForDid, DidKey};

#[tokio::test]
pub async fn usecase_generate_seed() {
    std::env::set_var("DID_POLITO_STRONGHOLD_CLIENT_PATH", "client");
    std::env::set_var("DID_POLITO_STRONGHOLD_BASE_VAULT_PATH", "vault");
    std::env::set_var("DID_POLITO_STRONGHOLD_BASE_RECORD_PATH", "record");
    std::env::set_var("DID_POLITO_DATA_CLIENT_PATH", "client_path");
    std::env::set_var("DID_POLITO_SNAPSHOT_PATH",  "./example.stronghold");

    let seed_generator = SeedGeneratorForDid {
        contract_address: "0xfd59a6f6f4537945a5ce98f32200d96df6a3809e".to_string(),
        passphrase: "TEST_POLITO".to_string(),
    };

    let result = seed_generator.generate_seed().unwrap();
    print!("mnemonic: {}", result);

}

#[tokio::test]
pub async fn usecase_add_key() {
    std::env::set_var("DID_POLITO_STRONGHOLD_CLIENT_PATH", "client");
    std::env::set_var("DID_POLITO_STRONGHOLD_BASE_VAULT_PATH", "vault");
    std::env::set_var("DID_POLITO_STRONGHOLD_BASE_RECORD_PATH", "record");
    std::env::set_var("DID_POLITO_DATA_CLIENT_PATH", "client_path");
    std::env::set_var("DID_POLITO_SNAPSHOT_PATH", "./example.stronghold");

    let add_key_generator = DidKey {
        passphrase: "TEST_POLITO".to_string(),
        contract_address: "0xfd59a6f6f4537945a5ce98f32200d96df6a3809e".to_string(),
        registry: 1,
        method_type: 1,
        verification_method: 1,
        index: 0
    };

    unsafe {
        let result = add_key_generator.add_did_key().unwrap();
        print!("public key hex: {:x?}", result.1);
    }
}

#[tokio::test]
pub async fn usecase_remove_key() {
    std::env::set_var("DID_POLITO_STRONGHOLD_CLIENT_PATH", "client");
    std::env::set_var("DID_POLITO_STRONGHOLD_BASE_VAULT_PATH", "vault");
    std::env::set_var("DID_POLITO_STRONGHOLD_BASE_RECORD_PATH", "record");
    std::env::set_var("DID_POLITO_DATA_CLIENT_PATH", "client_path");
    std::env::set_var("DID_POLITO_SNAPSHOT_PATH", "./example.stronghold");

    let remove_key_generator = DidKey {
        passphrase: "TEST_POLITO".to_string(),
        contract_address: "0xfd59a6f6f4537945a5ce98f32200d96df6a3809e".to_string(),
        registry: 1,
        method_type: 1,
        verification_method: 1,
        index: 0
    };

    unsafe {
        let result = remove_key_generator.remove_did_key().unwrap();
        println!("record path hex: {:x?}, result: {}", result.0, result.1);
    }
}
