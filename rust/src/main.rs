use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs,
    time::{SystemTime, UNIX_EPOCH},
};
use bitcoin::consensus::encode::serialize;
use bitcoin::{Transaction as BitcoinTransaction, TxIn, TxOut, Script, OutPoint};

const BLOCK_REWARD: u64 = 3_125_000_000; // 3.125 BTC in satoshis
const PREV_BLOCK_HASH: &str = "0000abcd00000000000000000000000000000000000000000000000000000000"; // some dummy hash
const DIFFICULTY_TARGET: &str = "0000ffff00000000000000000000000000000000000000000000000000000000";

#[derive(Debug, Deserialize)]
struct Transaction {
    txid: String,
    version: i32,
    locktime: u32,
    vin: Vec<Vin>,
    vout: Vec<Vout>,
    size: u32,
    weight: u64,
    fee: u64,
    status: Status,
    hex: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Vin {
    txid: String,
    vout: u32,
    prevout: Vout,
    scriptsig: String,
    scriptsig_asm: String,
    witness: Option<Vec<String>>,
    is_coinbase: bool,
    sequence: u64,
}

#[derive(Debug, Deserialize)]
struct Vout {
    scriptpubkey: String,
    scriptpubkey_type: String,
    scriptpubkey_address: Option<String>,
    value: u64,
}

#[derive(Debug, Deserialize)]
struct Status {
    confirmed: bool,
    block_height: u32,
    block_hash: String,
    block_time: u64,
}

#[derive(Debug, Serialize, Deserialize)]
struct BlockHeader {
    version: i32,
    prev_block_hash: String,
    merkle_root: String,
    time: u32,
    bits: u32,
    nonce: u32,
}

impl BlockHeader {
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![];

        // Serialize each field in little-endian format
        bytes.extend(&self.version.to_le_bytes());
        bytes.extend(
            &hex::decode(&self.prev_block_hash)
                .unwrap()
                .into_iter()
                .rev()
                .collect::<Vec<_>>(),
        );
        bytes.extend(
            &hex::decode(&self.merkle_root)
                .unwrap()
                .into_iter()
                .rev()
                .collect::<Vec<_>>(),
        );
        bytes.extend(&self.time.to_le_bytes());
        bytes.extend(&self.bits.to_le_bytes());
        bytes.extend(&self.nonce.to_le_bytes());

        bytes
    }
}

fn main() {
    let reward_address = "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh"; // rando address

    let transactions = read_txs_from_mempool();
    let mined_block = mine_the_block(transactions, reward_address);

    output_results(mined_block)
}

fn read_txs_from_mempool() -> Vec<Transaction> {
    let mut transactions = Vec::new();

    for entry in fs::read_dir("mempool").unwrap() {
        let entry = entry.unwrap();
        let path = entry.path();

        if path.is_file() && path.file_name().unwrap() != "mempool.json" {
            let tx_str = fs::read_to_string(path).unwrap();
            let tx_data: Transaction = serde_json::from_str(&tx_str).unwrap();
            transactions.push(tx_data);
        }
    }
    transactions
}

fn mine_the_block(
    transactions: Vec<Transaction>,
    miner_address: &str,
) -> (BlockHeader, Vec<String>) {
    println!("Mining new block...");

    // Compile transactions, fees and coinbase transaction
    let (mut block_txs, total_fees) = compile_txs_and_fees_from_the_mempool(transactions);
    let coinbase_tx = create_coinbase_transaction(BLOCK_REWARD + total_fees, miner_address);
    block_txs.insert(0, coinbase_tx);

    // Compute merkle root
    let tx_ids: Vec<String> = block_txs.iter().map(|tx| tx.txid.clone()).collect();
    let tx_merkle_root = calculate_merkle_root(&tx_ids);

    let mut block_header = BlockHeader {
        version: 4,
        prev_block_hash: PREV_BLOCK_HASH.to_string(),
        merkle_root: tx_merkle_root,
        time: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as u32, // Should be block timestamp, doesn't matter right now
        bits: 0x1d00ffff, // Difficulty target
        nonce: 0,
    };

    let target = create_target();

    // Iterate with a difference nonce until the difficulty is satsified
    loop {
        // Let's do a progress counter for my own sanity check
        if block_header.nonce % 100000 == 0 {
            println!("Nonce: {}", block_header.nonce);
        }

        let block_hash = calculate_block_hash(&block_header);
        if meets_difficulty_target(&block_hash, target) {
            break;
        }
        block_header.nonce += 1;
    }

    println!("Final Nonce: {}", block_header.nonce);
    (block_header, tx_ids)
}

// TODO: Validate txs
// fn validate_the_txs() {
//      Idk what to do here yet
// }

fn create_coinbase_transaction(reward: u64, address: &str) -> Transaction {
    let coinbase_input = Vin {
        txid: "0".repeat(64), // Coinbase input txid is all zeros
        vout: 0,
        prevout: Vout {
            scriptpubkey: "".to_string(),
            scriptpubkey_type: "".to_string(),
            scriptpubkey_address: Some("".to_string()),
            value: 0,
        },
        scriptsig: "coinbase".to_string(), // Arbitrary data for scriptsig
        scriptsig_asm: "coinbase".to_string(), // Same as scriptsig for simplicity
        witness: Some(vec![]),
        is_coinbase: true,
        sequence: 0xffffffff,
    };

    let coinbase_output = Vout {
        scriptpubkey: format!("OP_DUP OP_HASH160 {} OP_EQUALVERIFY OP_CHECKSIG", address),
        scriptpubkey_type: "p2pkh".to_string(),
        scriptpubkey_address: Some(address.to_string()),
        value: reward,
    };

    Transaction {
        txid: "".to_string(), // This will be set later after serialization
        version: 1,
        locktime: 0,
        vin: vec![coinbase_input],
        vout: vec![coinbase_output],
        size: 0,   // This will be calculated later
        weight: 0, // This will be calculated later
        fee: 0,
        status: Status {
            confirmed: false,
            block_height: 0,
            block_hash: "".to_string(),
            block_time: 0,
        },
        hex: None, // This will be set later after serialization
    }
}


fn compile_txs_and_fees_from_the_mempool(
    transactions: Vec<Transaction>,
) -> (Vec<Transaction>, u64) {
    let mut compiled_txs: Vec<Transaction> = Vec::new();
    let mut total_weight = 0;
    let mut total_fees = 0;
    const MAX_WEIGHT: u64 = 4_000_000;

    for tx in transactions {
        total_weight += &tx.weight;
        if total_weight <= MAX_WEIGHT {
            total_fees += &tx.fee;
            compiled_txs.push(tx);
        } else {
            break;
        }
    }
    (compiled_txs, total_fees)
}

fn calculate_merkle_root(txids: &Vec<String>) -> String {
    if txids.is_empty() {
        return "".to_string();
    }

    // Convert tx ids to their hashes
    let mut tx_hashes: Vec<Vec<u8>> = txids
        .iter()
        .map(|txid| {
            let mut hasher = Sha256::new();
            hasher.update(hex::decode(txid).unwrap());
            hasher.finalize().to_vec()
        })
        .collect();

    // Build the merkle root
    while tx_hashes.len() > 1 {
        if tx_hashes.len() % 2 != 0 {
            tx_hashes.push(tx_hashes[tx_hashes.len() - 1].clone());
        }

        tx_hashes = tx_hashes
            .chunks(2)
            .map(|pair| {
                let mut hasher = Sha256::new();
                hasher.update([pair[0].as_slice(), pair[1].as_slice()].concat());
                hasher.finalize().to_vec()
            })
            .collect();
    }

    hex::encode(&tx_hashes[0])
}

fn calculate_block_hash(block_header: &BlockHeader) -> [u8; 32] {
    let serialized_header = block_header.to_bytes();
    let hash1 = Sha256::digest(&serialized_header);
    let hash2 = Sha256::digest(hash1); // tests show 2 sha hashes; I guess that's a bitcoin thing

    let mut hash = [0u8; 32];
    hash.copy_from_slice(&hash2);
    hash.reverse(); // reversed like the tests do

    hash
}

fn create_target() -> [u8; 32] {
    let target: [u8; 32] = hex::decode(DIFFICULTY_TARGET)
    .unwrap()
    .try_into()
    .expect("Difficulty should be 32 bytes");

    target
}

fn meets_difficulty_target(hash: &[u8; 32], target: [u8; 32]) -> bool {
    hash <= &target
}

fn output_results(mined_block: (BlockHeader, Vec<String>)) {
    let (block_header, tx_ids) = mined_block;
    let mut output = String::new();

    let serialized_header = block_header.to_bytes();
    let block_header_hex = hex::encode(serialized_header);

    // Write the block header
    output.push_str(&format!("{}", block_header_hex));

    // Write the transaction IDs
    for tx_id in tx_ids {
        output.push_str(&format!("{}\n", tx_id));
    }

    fs::write("out.txt", output).unwrap();
}