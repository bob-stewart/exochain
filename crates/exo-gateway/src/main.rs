//! decision.forum API server binary.

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();

    let port: u16 = std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(8080);

    // Use DATABASE_URL if set, otherwise fall back to in-memory mode
    match std::env::var("DATABASE_URL") {
        Ok(database_url) => {
            println!("[EXOCHAIN] Starting with PostgreSQL persistence");
            let pool = exo_gateway::db::init_pool(&database_url).await;
            exo_gateway::server::run_server_with_db(port, pool).await;
        }
        Err(_) => {
            println!("[EXOCHAIN] Starting in memory-only mode (no DATABASE_URL)");
            exo_gateway::server::run_server(port).await;
        }
    }
}
