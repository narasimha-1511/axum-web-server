use axum::{
    extract::Query,
    http::StatusCode,
    response::Json,
    routing::{get, post},
    Router,
};
use serde::{Deserialize, Serialize};
use solana_client::nonblocking::rpc_client::RpcClient;
use solana_sdk::{
    commitment_config::CommitmentConfig,
    native_token::LAMPORTS_PER_SOL,
    pubkey::Pubkey,
    signature::{Keypair, Signer},
};
use std::{str::FromStr};
use std::net::SocketAddr;
use tokio;
use base64::prelude::*;

#[derive(Serialize)]
struct ApiResponse {
    success: bool,
    message: String,
    data: Option<serde_json::Value>,
}

#[derive(Deserialize)]
struct AirdropQuery {
    address: String,
    amount: Option<f64>,
}

#[derive(Serialize)]
struct AccountInfo {
    public_key: String,
    private_key_bytes: String,
}

#[derive(Serialize)]
struct AirdropInfo {
    signature: String,
    explorer_url: String,
}

// Helper to create a Solana RPC client for devnet
fn get_rpc_client() -> RpcClient {
    RpcClient::new_with_commitment(
        "https://api.devnet.solana.com".to_string(),
        CommitmentConfig::confirmed(),
    )
}

#[tokio::main]
async fn main() {
    // Set up logging for the server
    tracing_subscriber::fmt::init();

    // Set up the application routes
    let app = Router::new()
        .route("/", get(root))
        .route("/health", get(health_check))
        .route("/create-account", post(create_account))
        .route("/airdrop", get(request_airdrop))
        .route("/balance", get(get_balance));

    // Read the port from the environment or use 3000
    let port: u16 = std::env::var("PORT")
        .unwrap_or_else(|_| "3000".to_string())
        .parse()
        .expect("Failed to parse PORT");

    // Bind to the specified port on all IPv6 interfaces
    let address = SocketAddr::from(([0,0,0,0,0,0,0,0], port));
    let listener = tokio::net::TcpListener::bind(&address).await.unwrap();

    
    println!("🚀 Server running on http://127.0.0.1:3000");
    println!("📋 Available endpoints:");
    println!("  GET  /              - Welcome message");
    println!("  GET  /health        - Health check");
    println!("  POST /create-account - Create new Solana account");
    println!("  GET  /airdrop       - Request SOL airdrop (requires ?address=<pubkey>&amount=<sol>)");
    println!("  GET  /balance       - Get account balance (requires ?address=<pubkey>)");
    
    axum::serve(listener, app).await.unwrap();
}

// Shows a welcome message and available endpoints
async fn root() -> Json<ApiResponse> {
    Json(ApiResponse {
        success: true,
        message: "🔗 Solana Rust Server is running!".to_string(),
        data: Some(serde_json::json!({
            "endpoints": [
                "GET /health - Health check",
                "POST /create-account - Create new Solana account",
                "GET /airdrop?address=<pubkey>&amount=<sol> - Request SOL airdrop",
                "GET /balance?address=<pubkey> - Get account balance"
            ]
        })),
    })
}

// Checks if the Solana RPC node is healthy
async fn health_check() -> Json<ApiResponse> {
    let client = get_rpc_client();
    
    match client.get_health().await {
        Ok(_) => Json(ApiResponse {
            success: true,
            message: "Server and Solana RPC are healthy".to_string(),
            data: None,
        }),
        Err(e) => Json(ApiResponse {
            success: false,
            message: format!("Solana RPC health check failed: {}", e),
            data: None,
        }),
    }
}

// Generates a new Solana keypair and returns the public and private key
async fn create_account() -> (StatusCode, Json<ApiResponse>) {
    let keypair = Keypair::new();
    let public_key = keypair.pubkey().to_string();
    
    // Convert private key to bytes for storage/backup purposes using new base64 API
    let private_key_bytes = BASE64_STANDARD.encode(&keypair.to_bytes());
    
    let account_info = AccountInfo {
        public_key: public_key.clone(),
        private_key_bytes,
    };
    
    (
        StatusCode::CREATED,
        Json(ApiResponse {
            success: true,
            message: "🔑 New Solana account created successfully!".to_string(),
            data: Some(serde_json::to_value(account_info).unwrap()),
        }),
    )
}

// Handles airdrop requests for a given address and amount
async fn request_airdrop(Query(params): Query<AirdropQuery>) -> (StatusCode, Json<ApiResponse>) {
    let client = get_rpc_client();
    
    // Try to parse the provided address string into a Pubkey
    let pubkey = match Pubkey::from_str(&params.address) {
        Ok(pk) => pk,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ApiResponse {
                    success: false,
                    message: "❌ Invalid public key format".to_string(),
                    data: None,
                }),
            );
        }
    };
    
    // Use 1 SOL if no amount is specified
    let sol_amount = params.amount.unwrap_or(1.0);
    let lamports = (sol_amount * LAMPORTS_PER_SOL as f64) as u64;
    
    // Request the airdrop from the Solana devnet
    match client.request_airdrop(&pubkey, lamports).await {
        Ok(signature) => {
            let explorer_url = format!(
                "https://explorer.solana.com/tx/{}?cluster=devnet",
                signature
            );
            
            let airdrop_info = AirdropInfo {
                signature: signature.to_string(),
                explorer_url,
            };
            
            (
                StatusCode::OK,
                Json(ApiResponse {
                    success: true,
                    message: format!("💰 Successfully airdropped {} SOL!", sol_amount),
                    data: Some(serde_json::to_value(airdrop_info).unwrap()),
                }),
            )
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiResponse {
                success: false,
                message: format!("❌ Airdrop failed: {}", e),
                data: None,
            }),
        ),
    }
}

// Returns the SOL and lamport balance for a given address
async fn get_balance(Query(params): Query<AirdropQuery>) -> (StatusCode, Json<ApiResponse>) {
    let client = get_rpc_client();
    
    let pubkey = match Pubkey::from_str(&params.address) {
        Ok(pk) => pk,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ApiResponse {
                    success: false,
                    message: "❌ Invalid public key format".to_string(),
                    data: None,
                }),
            );
        }
    };
    
    match client.get_balance(&pubkey).await {
        Ok(balance_lamports) => {
            let balance_sol = balance_lamports as f64 / LAMPORTS_PER_SOL as f64;
            
            (
                StatusCode::OK,
                Json(ApiResponse {
                    success: true,
                    message: "💳 Balance retrieved successfully".to_string(),
                    data: Some(serde_json::json!({
                        "address": params.address,
                        "balance_sol": balance_sol,
                        "balance_lamports": balance_lamports
                    })),
                }),
            )
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiResponse {
                success: false,
                message: format!("❌ Failed to get balance: {}", e),
                data: None,
            }),
        ),
    }
}