use serde::{Deserialize, Serialize};
use solana_sdk::{
    pubkey::Pubkey,
    signature::{Keypair, Signature, Signer},
};
use axum::{
    extract::Json as extJson,
    http::StatusCode,
    response::Json,
    routing::post,
    Router,
};
use spl_associated_token_account;
use tower_http::cors::{Any, CorsLayer};
use spl_token::instruction::{initialize_mint, mint_to, transfer};
use solana_program::system_instruction;
use base64::prelude::*;
use std::str::FromStr;
use bs58;



// Token account info
#[derive(Serialize)]
struct TokenAccountInfo {
    pubkey: String,
    #[serde(rename = "isSigner")]
    is_signer: bool,
}

// Request struct for create token
#[derive(Deserialize, Debug)]
struct CreateTokenRequest {
    #[serde(rename = "mintAuthority")]
    mint_authority: Option<String>,
    mint: Option<String>,
    decimals: Option<u8>,
}

impl CreateTokenRequest {
    // Check all field present and valid
    fn validate(&self) -> Result<(), String> {
        if self.mint_authority.as_ref().map(|m| m.trim().is_empty()).unwrap_or(true) {
            return Err("mintAuthority is required".to_string());
        }
        if self.mint_authority.as_ref().map(|m| !is_valid_pubkey(m)).unwrap_or(false) {
            return Err("mintAuthority is not a valid Solana public key".to_string());
        }
        if self.mint.as_ref().map(|m| m.trim().is_empty()).unwrap_or(true) {
            return Err("mint is required".to_string());
        }
        if self.mint.as_ref().map(|m| !is_valid_pubkey(m)).unwrap_or(false) {
            return Err("mint is not a valid Solana public key".to_string());
        }
        Ok(())
    }
}

// Request struct for mint token
#[derive(Deserialize, Debug)]
struct MintTokenRequest {
    mint: Option<String>,
    destination: String,
    authority: String,
    amount: u64,
}

impl MintTokenRequest {
    // Check required field and amount > 0
    fn validate(&self) -> Result<(), String> {
        if self.mint.as_ref().map(|m| m.trim().is_empty()).unwrap_or(true) {
            return Err("mint is required".to_string());
        }
        if self.destination.trim().is_empty() {
            return Err("destination is required".to_string());
        }
        if self.authority.trim().is_empty() {
            return Err("authority is required".to_string());
        }
        if self.amount == 0 {
            return Err("amount must be greater than 0".to_string());
        }
        Ok(())
    }
    // If mint not present, use authority
    fn get_mint(&self) -> String {
        match &self.mint {
            Some(m) if !m.trim().is_empty() => m.clone(),
            _ => self.authority.clone(),
        }
    }
}

// Request struct for sign message
#[derive(Deserialize, Debug)]
struct SignMessageRequest {
    message: String,
    secret: String,
}

impl SignMessageRequest {
    // Check message and secret present
    fn validate(&self) -> Result<(), String> {
        if self.message.trim().is_empty() {
            return Err("message is required".to_string());
        }
        if self.secret.trim().is_empty() {
            return Err("secret is required".to_string());
        }
        Ok(())
    }
}

// Request struct for verify message
#[derive(Deserialize, Debug)]
struct VerifyMessageRequest {
    message: Option<String>,
    signature: Option<String>,
    pubkey: Option<String>,
}

impl VerifyMessageRequest {
    // Check all three field present
    fn validate(&self) -> Result<(), String> {
        let mut missing = vec![];
        if self.message.as_ref().map(|s| s.trim().is_empty()).unwrap_or(true) {
            missing.push("message");
        }
        if self.signature.as_ref().map(|s| s.trim().is_empty()).unwrap_or(true) {
            missing.push("signature");
        }
        if self.pubkey.as_ref().map(|s| s.trim().is_empty()).unwrap_or(true) {
            missing.push("pubkey");
        }
        if !missing.is_empty() {
            return Err(format!("Missing required field(s): {}", missing.join(", ")));
        }
        Ok(())
    }
}

// Request struct for send sol
#[derive(Deserialize, Debug)]
struct SendSolRequest {
    from: String,
    to: String,
    lamports: u64,
}

impl SendSolRequest {
    // Check from, to and lamports > 0
    fn validate(&self) -> Result<(), String> {
        if self.from.trim().is_empty() {
            return Err("from is required".to_string());
        }
        if self.to.trim().is_empty() {
            return Err("to is required".to_string());
        }
        if self.lamports == 0 {
            return Err("lamports must be greater than 0".to_string());
        }
        Ok(())
    }
}

// Request struct for send token
#[derive(Deserialize, Debug)]
struct SendTokenRequest {
    destination: Option<String>,
    mint: Option<String>,
    owner: Option<String>,
    amount: Option<u64>,
}

impl SendTokenRequest {
    // Check all field present, amount > 0
    fn validate(&self) -> Result<(), String> {
        let mut missing = vec![];
        if self.destination.as_ref().map(|s| s.trim().is_empty()).unwrap_or(true) {
            missing.push("destination");
        }
        if self.mint.as_ref().map(|s| s.trim().is_empty()).unwrap_or(true) {
            missing.push("mint");
        }
        if self.owner.as_ref().map(|s| s.trim().is_empty()).unwrap_or(true) {
            missing.push("owner");
        }
        if self.amount.is_none() {
            missing.push("amount");
        } else if self.amount == Some(0) {
            return Err("amount must be greater than 0".to_string());
        }
        if !missing.is_empty() {
            return Err(format!("Missing required field(s): {}", missing.join(", ")));
        }
        Ok(())
    }
}

// Response struct for API
#[derive(Serialize)]
struct ApiResponse<T> {
    success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

// Keypair data struct
#[derive(Serialize)]
struct KeypairData {
    pubkey: String,
    secret: String,
}

// Generic instruction data
#[derive(Serialize)]
struct InstructionData {
    program_id: String,
    accounts: Vec<AccountInfo>,
    instruction_data: String,
}

// Token create instruction data
#[derive(Serialize)]
struct CreateTokenInstructionData {
    program_id: String,
    accounts: Vec<AccountInfo>,
    instruction_data: String,
}

// Account info struct
#[derive(Serialize)]
struct AccountInfo {
    pubkey: String,
    is_signer: bool,
    is_writable: bool,
}

// Signature data struct
#[derive(Serialize)]
struct SignatureData {
    signature: String,
    public_key: String,
    message: String,
}

// Verification result struct
#[derive(Serialize)]
struct VerificationData {
    valid: bool,
    message: String,
    pubkey: String,
}

// SOL transfer data
#[derive(Serialize)]
struct TransferData {
    program_id: String,
    accounts: Vec<String>,
    instruction_data: String,
}

// Token transfer data
#[derive(Serialize)]
struct TokenTransferData {
    program_id: String,
    accounts: Vec<TokenAccountInfo>,
    instruction_data: String,
}


// Check if pubkey valid
fn is_valid_pubkey(s: &str) -> bool {
    Pubkey::from_str(s).is_ok()
}

// Make error response
fn error_response<T>(message: &str) -> (StatusCode, Json<ApiResponse<T>>) {
    (
        StatusCode::BAD_REQUEST,
        Json(ApiResponse {
            success: false,
            data: None,
            error: Some(message.to_string()),
        })
    )
}

// Make success response
fn success_response<T>(data: T) -> Json<ApiResponse<T>> {
    Json(ApiResponse {
        success: true,
        data: Some(data),
        error: None,
    })
}

// Main function
#[tokio::main]
async fn main() {
    // Setup CORS
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    // Setup routes
    let app = Router::new()
        .route("/keypair", post(generate_keypair))
        .route("/token/create", post(create_token))
        .route("/token/mint", post(mint_token))
        .route("/message/sign", post(sign_message))
        .route("/message/verify", post(verify_message))
        .route("/send/sol", post(send_sol))
        .route("/send/token", post(send_token))
        .layer(cors);

    // Bind to localhost:3000
    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000")
        .await
        .unwrap();
    println!("Server running on http://127.0.0.1:3000");
    // Serve app
    axum::serve(listener, app).await.unwrap();
}

// This make keypair
async fn generate_keypair() -> Json<ApiResponse<KeypairData>> {
    let keypair = Keypair::new();
    let pubkey = bs58::encode(keypair.pubkey().as_ref()).into_string();
    let secret = bs58::encode(&keypair.to_bytes()).into_string();
    println!("Keypair generated for pubkey: {}", pubkey);
    success_response(KeypairData { pubkey, secret })
}

// This make token create instruction
async fn create_token(
    extJson(payload): extJson<CreateTokenRequest>,
) -> (StatusCode, Json<ApiResponse<CreateTokenInstructionData>>) {
    if let Err(msg) = payload.validate() {
        println!("Error: {}", msg);
        return error_response(&msg);
    }
    let mint_authority = match Pubkey::from_str(&payload.mint_authority.as_ref().unwrap()) {
        Ok(pk) => pk,
        Err(e) => {
            println!("Invalid mint authority pubkey: {:?}", payload.mint_authority);
            return error_response("Invalid mint authority public key")
        },
    };
    let mint = match Pubkey::from_str(&payload.mint.as_ref().unwrap()) {
        Ok(pk) => pk,
        Err(e) => {
            println!("Invalid mint pubkey: {:?}", payload.mint);
            return error_response("Invalid mint public key")
        },
    };
    let instruction = match initialize_mint(
        &spl_token::id(),
        &mint,
        &mint_authority,
        Some(&mint_authority),
        payload.decimals.unwrap(),
    ) {
        Ok(inst) => inst,
        Err(e) => {
            println!("Failed to create mint instruction: {}", e);
            return error_response("Failed to create mint instruction")
        },
    };
    let accounts = instruction.accounts.iter().map(|acc| AccountInfo {
        pubkey: acc.pubkey.to_string(),
        is_signer: acc.is_signer,
        is_writable: acc.is_writable,
    }).collect();
    let instruction_data = CreateTokenInstructionData {
        program_id: instruction.program_id.to_string(),
        accounts,
        instruction_data: BASE64_STANDARD.encode(&instruction.data),
    };
    println!("Token instruction created for mint {}", payload.mint.as_ref().unwrap());
    (StatusCode::OK, success_response(instruction_data))
}

// This make mint token instruction
async fn mint_token(
    extJson(payload): extJson<MintTokenRequest>,
) -> (StatusCode, Json<ApiResponse<InstructionData>>) {
    if let Err(msg) = payload.validate() {
        println!("Error: {}", msg);
        return error_response(&msg);
    }
    let mint_str = payload.get_mint();
    let mint = match Pubkey::from_str(&mint_str) {
        Ok(pk) => pk,
        Err(e) => {
            println!("Invalid mint pubkey: {}", mint_str);
            return error_response("Invalid mint public key")
        },
    };
    let destination = match Pubkey::from_str(&payload.destination) {
        Ok(pk) => pk,
        Err(e) => {
            println!("Invalid destination pubkey: {}", payload.destination);
            return error_response("Invalid destination public key")
        },
    };
    let authority = match Pubkey::from_str(&payload.authority) {
        Ok(pk) => pk,
        Err(e) => {
            println!("Invalid authority pubkey: {}", payload.authority);
            return error_response("Invalid authority public key")
        },
    };
    let instruction = match mint_to(
        &spl_token::id(),
        &mint,
        &destination,
        &authority,
        &[],
        payload.amount,
    ) {
        Ok(inst) => inst,
        Err(e) => {
            println!("Failed to create mint_to instruction: {}", e);
            return error_response("Failed to create mint instruction")
        },
    };
    let accounts = instruction.accounts.iter().map(|acc| AccountInfo {
        pubkey: acc.pubkey.to_string(),
        is_signer: acc.is_signer,
        is_writable: acc.is_writable,
    }).collect();
    let instruction_data = InstructionData {
        program_id: instruction.program_id.to_string(),
        accounts,
        instruction_data: BASE64_STANDARD.encode(&instruction.data),
    };
    (StatusCode::OK, success_response(instruction_data))
}

// This sign message
async fn sign_message(
    extJson(payload): extJson<SignMessageRequest>,
) -> (StatusCode, Json<ApiResponse<SignatureData>>) {
    if let Err(msg) = payload.validate() {
        println!("Error: {}", msg);
        return error_response(&msg);
    }
    let secret_bytes = match bs58::decode(&payload.secret).into_vec() {
        Ok(bytes) => bytes,
        Err(e) => {
            println!("Invalid secret key format (bs58 decode failed): {}", e);
            return error_response("Invalid secret key format")
        },
    };
    let keypair = match Keypair::try_from(&secret_bytes[..]) {
        Ok(kp) => kp,
        Err(e) => {
            println!("Invalid secret key: {}", e);
            return error_response("Invalid secret key")
        },
    };
    let message_bytes = payload.message.as_bytes();
    let signature = keypair.sign_message(message_bytes);
    let public_key = bs58::encode(keypair.pubkey().as_ref()).into_string();
    let signature_data = SignatureData {
        signature: BASE64_STANDARD.encode(signature.as_ref()),
        public_key,
        message: payload.message,
    };
    println!("Message signed for pubkey {}", signature_data.public_key);
    (StatusCode::OK, success_response(signature_data))
}

// This verify message
async fn verify_message(
    extJson(payload): extJson<VerifyMessageRequest>,
) -> (StatusCode, Json<ApiResponse<VerificationData>>) {
    if let Err(msg) = payload.validate() {
        println!("Error: {}", msg);
        return error_response(&msg);
    }
    let pubkey = match Pubkey::from_str(&payload.pubkey.as_ref().unwrap()) {
        Ok(pk) => pk,
        Err(e) => {
            println!("Invalid pubkey format: {:?}", payload.pubkey);
            return error_response("Invalid public key format")
        },
    };
    let signature_bytes = match BASE64_STANDARD.decode(&payload.signature.as_ref().unwrap()) {
        Ok(bytes) => bytes,
        Err(e) => {
            println!("Invalid signature format (base64 decode failed): {}", e);
            return error_response("Invalid signature format")
        },
    };
    let signature = match Signature::try_from(signature_bytes.as_slice()) {
        Ok(sig) => sig,
        Err(e) => {
            println!("Invalid signature: {}", e);
            return error_response("Invalid signature")
        },
    };
    let message_bytes = payload.message.as_ref().unwrap().as_bytes();
    let is_valid = signature.verify(pubkey.as_ref(), message_bytes);
    let verification_data = VerificationData {
        valid: is_valid,
        message: payload.message.as_ref().unwrap().clone(),
        pubkey: pubkey.to_string(),
    };
    (StatusCode::OK, success_response(verification_data))
}

// This make SOL transfer instruction
async fn send_sol(
    extJson(payload): extJson<SendSolRequest>,
) -> (StatusCode, Json<ApiResponse<TransferData>>) {
    if let Err(msg) = payload.validate() {
        println!("Error: {}", msg);
        return error_response(&msg);
    }
    let from = match Pubkey::from_str(&payload.from) {
        Ok(pk) => pk,
        Err(e) => {
            println!("Invalid from address: {}", payload.from);
            return error_response("Invalid from address")
        },
    };
    let to = match Pubkey::from_str(&payload.to) {
        Ok(pk) => pk,
        Err(e) => {
            println!("Invalid to address: {}", payload.to);
            return error_response("Invalid to address")
        },
    };
    if payload.lamports == 0 {
        println!("Amount must be greater than 0, got {}", payload.lamports);
        return error_response("Amount must be greater than 0");
    }
    let instruction = system_instruction::transfer(&from, &to, payload.lamports);
    let accounts = instruction.accounts.iter().map(|acc| acc.pubkey.to_string()).collect();
    let transfer_data = TransferData {
        program_id: instruction.program_id.to_string(),
        accounts,
        instruction_data: BASE64_STANDARD.encode(&instruction.data),
    };
    (StatusCode::OK, success_response(transfer_data))
}

// This make token transfer instruction
async fn send_token(
    extJson(payload): extJson<SendTokenRequest>,
) -> (StatusCode, Json<ApiResponse<TokenTransferData>>) {
    if let Err(msg) = payload.validate() {
        println!("Error: {}", msg);
        return error_response(&msg);
    }
    let destination = match Pubkey::from_str(payload.destination.as_ref().unwrap()) {
        Ok(pk) => pk,
        Err(e) => {
            println!("Invalid destination address: {:?}", payload.destination);
            return error_response("Invalid destination address")
        },
    };
    let mint = match Pubkey::from_str(payload.mint.as_ref().unwrap()) {
        Ok(pk) => pk,
        Err(e) => {
            println!("Invalid mint address: {:?}", payload.mint);
            return error_response("Invalid mint address")
        },
    };
    let owner = match Pubkey::from_str(payload.owner.as_ref().unwrap()) {
        Ok(pk) => pk,
        Err(e) => {
            println!("Invalid owner address: {:?}", payload.owner);
            return error_response("Invalid owner address")
        },
    };
    let amount = payload.amount.unwrap();
    if amount == 0 {
        println!("Amount must be greater than 0, got {}", amount);
        return error_response("Amount must be greater than 0");
    }
    let source_ata = spl_associated_token_account::get_associated_token_address(&owner, &mint);
    let dest_ata = spl_associated_token_account::get_associated_token_address(&destination, &mint);
    let instruction = match transfer(
        &spl_token::id(),
        &source_ata,
        &dest_ata,
        &owner,
        &[],
        amount,
    ) {
        Ok(inst) => inst,
        Err(e) => {
            println!("Failed to create token transfer instruction: {}", e);
            return error_response("Failed to create token transfer instruction")
        },
    };
    let accounts = instruction.accounts.iter().map(|acc| TokenAccountInfo {
        pubkey: acc.pubkey.to_string(),
        is_signer: acc.is_signer,
    }).collect();
    let transfer_data = TokenTransferData {
        program_id: instruction.program_id.to_string(),
        accounts,
        instruction_data: BASE64_STANDARD.encode(&instruction.data),
    };
    (StatusCode::OK, success_response(transfer_data))
}
