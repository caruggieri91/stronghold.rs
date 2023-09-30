use serde::{Deserialize, Serialize};
use stronghold_utils::GuardDebug;

use super::{FatalProcedureError, ProcedureError};

use crate::{
    procedures::{
        BIP39Generate,
        DeriveSecret, Ed25519Sign, GenerateKey, GenerateSecret, KeyType,
        MnemonicLanguage, PublicKey, Slip10Derive, Slip10DeriveInput, Slip10Generate, StrongholdProcedure,
        X25519DiffieHellman, DidKeyDeriveInput, DidKeyDerive
    },
    Client, Location, Stronghold, ClientError,
};
use crypto::signatures::ed25519;

const PURPOSE: u32 = 1361;
const HARDEN_MASK: u32 = 1 << 31;

pub struct SeedGeneratorForDid {
    pub passphrase: String,
    pub contract_address: String
}

impl SeedGeneratorForDid {
    /// This function generate a BIP-39 seed and return its mnemonic
    pub fn generate_seed(&self) -> Result<String, ProcedureError> {
        // Generate a BIP39 seed or retrieve from Location
        let stronghold: Stronghold = Stronghold::default();
        let client: Client = stronghold.create_client(std::env::var("DID_POLITO_STRONGHOLD_CLIENT_PATH").expect("$DID_POLITO_STRONGHOLD_CLIENT_PATH must be set.")).unwrap();

        let passphrase: String = self.passphrase.clone();
        let vault_path = std::env::var("DID_POLITO_STRONGHOLD_BASE_VAULT_PATH").expect("$DID_POLITO_STRONGHOLD_BASE_VAULT_PATH must be set.") + "_" + self.contract_address.as_str();
        let record_path: String = std::env::var("DID_POLITO_STRONGHOLD_BASE_RECORD_PATH").expect("$DID_POLITO_STRONGHOLD_BASE_RECORD_PATH must be set.") + "_seed_and_address_" + self.contract_address.as_str();
        let location: Location = Location::generic(vault_path.clone().as_bytes(), record_path.clone().as_bytes());

        let generate_bip39 = BIP39Generate {
            language: MnemonicLanguage::English,
            passphrase: Some(passphrase.clone()),
            output: location.clone(),
        };
    
        let generate_bip39_result = client.execute_procedure(generate_bip39);

        if generate_bip39_result.is_ok() {
            Ok(generate_bip39_result.ok().unwrap())
        } else {
            Err(generate_bip39_result.err().unwrap())
        }
    }
}

#[derive(Clone, GuardDebug, Serialize, Deserialize)]
pub struct DidKey {
    pub contract_address: String,
    pub registry: u32,
    pub method_type: u32,
    pub verification_method: u32, 
    pub index: u32,
}

impl DidKey {
    pub unsafe fn add_did_key(&self) -> Result<(Vec<u8>, Vec<u8>), ProcedureError> {
        let stronghold: Stronghold = Stronghold::default();
        let client: Client = stronghold.get_client(std::env::var("DID_POLITO_STRONGHOLD_CLIENT_PATH").expect("$DID_POLITO_STRONGHOLD_CLIENT_PATH must be set.")).unwrap();
        // Vault path
        let vault_path = std::env::var("DID_POLITO_STRONGHOLD_BASE_VAULT_PATH").expect("$DID_POLITO_STRONGHOLD_BASE_VAULT_PATH must be set.") + "_" + self.contract_address.as_str();
        // Seed path and location for seed
        let seed_record_path = std::env::var("DID_POLITO_STRONGHOLD_BASE_RECORD_PATH").expect("$DID_POLITO_STRONGHOLD_BASE_RECORD_PATH must be set.") + "_seed_and_address_" + self.contract_address.as_str();
        let seed_location = Location::generic(vault_path.clone().as_bytes(), seed_record_path.clone().as_bytes());
        // Key path and location for key
        // Key path is a vector composed by purpose + registry + method_type + verification_method + index
        let key_record_path = Vec::from([PURPOSE | HARDEN_MASK, self.registry | HARDEN_MASK, self.method_type | HARDEN_MASK, 
            self.verification_method | HARDEN_MASK, self.index | HARDEN_MASK]);
        let key_location = Location::generic(vault_path.clone(), key_record_path.clone().align_to::<u8>().1.to_vec());
        
        // Generate derived private key and store it
        let did_key_derive: DidKeyDerive = DidKeyDerive {
            input: DidKeyDeriveInput::Seed(seed_location.clone()),
            registry: self.registry,
            method_type: self.method_type,
            contract_addr: self.contract_address.clone(),
            verification_method: self.verification_method,
            index: self.index,
            output: key_location.clone(),
        };
    
        let did_key_derive_result = client.execute_procedure(did_key_derive);
        if did_key_derive_result.is_ok() {
            // Retrieve a public key and return its bytes
            let ed25519_pk = PublicKey {
                private_key: key_location.clone(),
                ty: KeyType::Ed25519,
            };
            let pk: [u8; ed25519::PUBLIC_KEY_LENGTH] = client.execute_procedure(ed25519_pk).unwrap();
            Ok((key_record_path.clone().align_to::<u8>().1.to_vec(), pk.to_vec()))
        } else {
            Err(did_key_derive_result.err().unwrap())
        }
    }

    pub unsafe fn remove_did_key(&self) -> Result<(Vec<u8>, bool), ClientError> {
        let stronghold: Stronghold = Stronghold::default();
        let client: Client = stronghold.get_client(std::env::var("DID_POLITO_STRONGHOLD_CLIENT_PATH").expect("$DID_POLITO_STRONGHOLD_CLIENT_PATH must be set.")).unwrap();
        // Vault path
        let vault_path = std::env::var("DID_POLITO_STRONGHOLD_BASE_VAULT_PATH").expect("$DID_POLITO_STRONGHOLD_BASE_VAULT_PATH must be set.") + "_" + self.contract_address.as_str();
        
        // Key location and key record path
        let key_record_path = Vec::from([PURPOSE | HARDEN_MASK, self.registry | HARDEN_MASK, self.method_type | HARDEN_MASK, 
            self.verification_method | HARDEN_MASK, self.index | HARDEN_MASK]);
        let key_location = Location::generic(vault_path.clone(), key_record_path.clone().align_to::<u8>().1.to_vec());

        // Check if record exists in vault
        let rec_exists_result = client.record_exists(&key_location.clone());
        if rec_exists_result.is_ok() {
            // If exists then delete secret into vault else return false for this key
            let exists = rec_exists_result.unwrap();
            if exists {
                // Delete secret into vault
                let delete_key_result = client.vault(vault_path.clone()).delete_secret(key_record_path.clone().align_to::<u8>().1.to_vec());
                if delete_key_result.is_ok() {
                    let res = delete_key_result.unwrap();
                    Ok((key_record_path.clone().align_to::<u8>().1.to_vec(), res))
                } else {
                    Err(delete_key_result.err().unwrap())
                }
            } else {
                Ok((key_record_path.clone().align_to::<u8>().1.to_vec(), false))
            }
        } else {
            Err(rec_exists_result.err().unwrap())
        }
    }
} 