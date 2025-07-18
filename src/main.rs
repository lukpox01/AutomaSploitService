use actix_web::{web, App, HttpResponse, HttpServer, Responder, middleware::Logger};
use actix_web::middleware::DefaultHeaders;
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::{self, BufRead};
use std::path::Path;
use std::process::{Command, Stdio};
use log::{error, info, log, warn};
use env_logger::Env;
use std::net::UdpSocket;
use serde_json;
use bytes::Bytes;
use reqwest::Client;
use futures::StreamExt;
use async_stream::try_stream;
use std::collections::HashMap;
use tokio::net::TcpStream;

const APP_PORTS: &[u16] = &[8084]; // Add any other ports your application uses

fn get_local_ip() -> Option<String> {
    let socket = match UdpSocket::bind("0.0.0.0:0") {
        Ok(s) => s,
        Err(_) => return None,
    };
    
    match socket.connect("8.8.8.8:80") {
        Ok(()) => (),
        Err(_) => return None,
    };
    
    match socket.local_addr() {
        Ok(addr) => Some(addr.ip().to_string()),
        Err(_) => None,
    }
}

// Helper function to adjust command for Windows.
fn get_command(command: &str) -> Command {
    let cmd = if cfg!(target_os = "windows") {
        format!("{}.exe", command)
    } else {
        command.to_string()
    };
    Command::new(cmd)
}

fn get_open_ports(ip: &str) -> Result<Vec<u16>, String> {
    let local_ip = get_local_ip().unwrap_or("unknown".to_string());
    let is_local = ip == local_ip || ip == "127.0.0.1" || ip == "localhost";
    let target_ip = if is_local { "127.0.0.1" } else { ip };
    
    info!("Executing rustscan on IP: {}", target_ip);
    let output_rustscan = get_command("rustscan")
        .arg("-a")
        .arg(target_ip)
        .arg("-g")
        .stderr(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .map_err(|e| {
            error!("Failed to execute rustscan: {}", e);
            format!("Failed to execute rustscan: {}", e)
        })?;

    let output = output_rustscan.wait_with_output().unwrap();

    if (!output.status.success()) {
        return Err(format!("rustscan failed: {}", String::from_utf8_lossy(&output.stderr)));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    info!("Rustscan output: {}", stdout);
    let ports: Vec<u16> = stdout
        .lines()
        .filter_map(|line| {
            if let Some(start) = line.find('[') {
                if let Some(end) = line.find(']') {
                    let ports_str = &line[start + 1..end];
                    return Some(
                        ports_str
                            .split(',')
                            .filter_map(|port_str| port_str.parse().ok())
                            .filter(|port| !is_local || !APP_PORTS.contains(port)) // Only filter APP_PORTS for local
                            .collect::<Vec<u16>>(),
                    );
                }
            }
            None
        })
        .flatten()
        .collect();

    Ok(ports)
}

fn scan_open_ports(ip: &str, ports: &[u16]) -> Result<String, String> {
    let local_ip = get_local_ip().unwrap_or("unknown".to_string());
    let target_ip = if ip == local_ip { "127.0.0.1" } else { ip };
    
    let ports_str = ports.iter().map(|p| p.to_string()).collect::<Vec<String>>().join(",");
    info!("Executing nmap scan on IP: {} for ports: {}", target_ip, ports_str);

    let output_nmap = get_command("nmap")
        .arg("-A")
        .arg(target_ip)
        .arg("-p")
        .arg(&ports_str)
        .stderr(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .map_err(|e| {
            error!("Failed to execute nmap: {}", e);
            format!("Failed to execute nmap: {}", e)
        })?;

    let output = output_nmap.wait_with_output().unwrap();

    if !output.status.success() {
        return Err(format!("nmap failed: {}", String::from_utf8_lossy(&output.stderr)));
    }

    let nmap_output = String::from_utf8_lossy(&output.stdout).to_string();
    // Log the raw Nmap output
    info!("Nmap output: {}", nmap_output);

    Ok(nmap_output)
}

#[derive(Debug, Serialize, Deserialize)]
struct Port {
    number: u16,
    service: String,
    protocol: String,
    state: String,
    application: String,
    details: Vec<String>, // Changed from one string to a list of strings
}

fn parse_nmap_output(nmap_output: &str, _is_local: bool) -> Result<Vec<Port>, String> {
    let mut results = Vec::new();
    let mut capture_ports = false;
    let mut current_port: Option<Port> = None;

    for line in nmap_output.lines() {
        if line.contains("PORT") && line.contains("STATE") && line.contains("SERVICE") {
            capture_ports = true;
            continue;
        }
        // Remove line.is_empty() from stopping capture
        if line.starts_with("Service detection performed.")
            || line.starts_with("Nmap done:")
        {
            capture_ports = false;
            if let Some(port) = current_port.take() {
                results.push(port);
            }
        }

        if capture_ports {
            // Detect new port lines more flexibly
            if (line.contains("/tcp") || line.contains("/udp")) && line.contains("open") {
                // Push old port if any
                if let Some(port) = current_port.take() {
                    results.push(port);
                }
                // Parse this new open port line
                let parts: Vec<&str> = line.split_whitespace().collect();
                let port_proto: Vec<&str> = parts[0].split('/').collect();
                if port_proto.len() > 1 {
                    let port_number = port_proto[0].parse::<u16>().unwrap_or(0);
                    let protocol = port_proto[1].to_string();
                    let state = parts[1].to_string();
                    let service = parts[2].to_string();
                    let application = if parts.len() > 3 {
                        parts[3..].join(" ")
                    } else {
                        "".to_string()
                    };

                    current_port = Some(Port {
                        number: port_number,
                        service,
                        protocol,
                        state,
                        application,
                        details: Vec::new(),
                    });
                }
            } else if line.trim_start().starts_with('|') {
                // Thread script lines into "details"
                if let Some(ref mut port) = current_port {
                    port.details.push(line.trim_start().to_string());
                }
            }
        } else if line.trim_start().starts_with('|') {
            // Store lines like "|_http-title: ..."
            if let Some(ref mut port) = current_port {
                port.details.push(line.trim_start().to_string());
            }
        }
    }

    // Handle last port if still active
    if let Some(port) = current_port {
        results.push(port);
    }

    Ok(results)
}

async fn scan(ip: web::Path<String>) -> impl Responder {
    let local_ip = get_local_ip().unwrap_or("unknown".to_string());
    let is_local = ip.as_str() == local_ip || ip.as_str() == "127.0.0.1" || ip.as_str() == "localhost";
    
    info!("Received scan request for IP: {} (is_local: {})", ip, is_local);
    match get_open_ports(&ip) {
        Ok(ports) => {
            if ports.is_empty() {
                info!("No open ports found for IP: {}", ip);
                return HttpResponse::Ok().json("N/A");
            }
            
            match scan_open_ports(&ip, &ports) {
                Ok(nmap_output) => {
                    match parse_nmap_output(&nmap_output, is_local) {
                        Ok(results) => HttpResponse::Ok().json(results),
                        Err(e) => HttpResponse::InternalServerError().body(format!("Error parsing nmap output: {}", e)),
                    }
                }
                Err(e) => HttpResponse::InternalServerError().body(format!("Error: {}", e)),
            }
        }
        Err(e) => HttpResponse::InternalServerError().body(format!("Error: {}", e)),
    }
}

#[derive(Debug, Serialize)]
struct NetworkScan {
    cidr: String,
    active_hosts: Vec<String>,
}

fn scan_network(cidr: &str) -> Result<Vec<String>, String> {
    let local_ip = get_local_ip().unwrap_or("unknown".to_string());
    info!("Local IP address: {}", local_ip);
    info!("Executing network scan on CIDR range: {}", cidr);
    let output = get_command("nmap")
        .arg("-sn")  // Ping scan
        .arg("-n")   // No DNS resolution
        .arg(cidr)
        .stderr(Stdio::piped())
        .stdout(Stdio::piped())
        .output()
        .map_err(|e| {
            error!("Failed to execute network scan: {}", e);
            format!("Failed to execute nmap network scan: {}", e)
        })?;

    if (!output.status.success()) {
        return Err(format!("Network scan failed: {}", String::from_utf8_lossy(&output.stderr)));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let active_hosts: Vec<String> = stdout
        .lines()
        .filter(|line| line.contains("Nmap scan report for"))
        .filter_map(|line| {
            line.split_whitespace()
                .nth(4)
                .map(|s| s.to_string())
        })
        .collect();

    Ok(active_hosts)
}

async fn discover_hosts(cidr: web::Path<String>) -> impl Responder {
    info!("Received network discovery request for CIDR: {}", cidr);
    let cidr = &cidr.replace("-", "/");
    match scan_network(&cidr) {
        Ok(hosts) => {
            let result = NetworkScan {
                cidr: cidr.to_string(),
                active_hosts: hosts,
            };
            HttpResponse::Ok().json(result)
        }
        Err(e) => HttpResponse::InternalServerError().body(e),
    }
}


// OpenRouter API structures
#[derive(Debug, Serialize, Deserialize)]
struct OpenRouterMessage {
    role: String,
    content: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct OpenRouterRequest {
    model: String,
    messages: Vec<OpenRouterMessage>,
    temperature: Option<f32>,
    max_tokens: Option<u32>,
}

#[derive(Debug, Serialize, Deserialize)]
struct OpenRouterChoice {
    message: OpenRouterMessage,
    finish_reason: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct OpenRouterResponse {
    id: String,
    choices: Vec<OpenRouterChoice>,
}

// Simplified question request struct
#[derive(Debug, Deserialize)]
struct QuestionRequest {
    question: String,
}

// Modified ask_openai handler to use OpenRouter
async fn ask_openai(client: web::Data<Client>, req: web::Json<QuestionRequest>) -> impl Responder {
    info!("Received question: {}", req.question);

    if req.question.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Question cannot be empty"
        }));
    }

    // Get OpenRouter API key from environment variable
    let api_key = match std::env::var("OPENROUTER_API_KEY") {
        Ok(key) => key,
        Err(_) => {
            error!("OPENROUTER_API_KEY environment variable not set");
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "OpenRouter API key not configured"
            }));
        }
    };

    let openrouter_request = OpenRouterRequest {
        model: "deepseek/deepseek-r1".to_string(), // Using DeepSeek R1 on OpenRouter
        messages: vec![
            OpenRouterMessage {
                role: "user".to_string(),
                content: req.question.clone(),
            }
        ],
        temperature: Some(0.7),
        max_tokens: Some(2048),
    };

    match client
        .post("https://openrouter.ai/api/v1/chat/completions")
        .header("Authorization", "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")
        .header("HTTP-Referer", "http://localhost:8084") 
        .header("X-Title", "AutomaSploitService")
        .json(&openrouter_request)
        .send()
        .await
    {
        Ok(response) => {
            if response.status().is_success() {
                match response.json::<OpenRouterResponse>().await {
                    Ok(openrouter_response) => {
                        if let Some(choice) = openrouter_response.choices.first() {
                            HttpResponse::Ok().json(serde_json::json!({
                                "text": choice.message.content
                            }))
                        } else {
                            error!("No choices in OpenRouter response");
                            HttpResponse::InternalServerError().json(serde_json::json!({
                                "error": "No response content from OpenRouter"
                            }))
                        }
                    }
                    Err(e) => {
                        error!("Failed to parse OpenRouter response: {}", e);
                        HttpResponse::InternalServerError().json(serde_json::json!({
                            "error": format!("Failed to parse response: {}", e)
                        }))
                    }
                }
            } else {
                error!("OpenRouter API error: {}", response.status());
                let error_text = response.text().await.unwrap_or_else(|_| "Unknown error".to_string());
                error!("OpenRouter error details: {}", error_text);
                HttpResponse::InternalServerError().json(serde_json::json!({
                    "error": format!("OpenRouter API error: {}", error_text)
                }))
            }
        }
        Err(e) => {
            error!("Error calling OpenRouter API: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": format!("Failed to call OpenRouter API: {}", e)
            }))
        }
    }
}

// Updated endpoint to check if all tools are installed with JSON output and detailed logs.
#[derive(Debug, Serialize)]
struct ToolStatus {
    installed: bool,
    running: bool,
}

async fn check_tools() -> impl Responder {
    let mut results: HashMap<String, ToolStatus> = HashMap::new();
    
    // Check rustscan and nmap first
    for tool in ["rustscan", "nmap"].iter() {
        info!("Checking tool: {}", tool);
        let installed = get_command(tool)
            .arg("--version")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
            
        info!("Tool {} installed: {}", tool, installed);
        results.insert(tool.to_string(), ToolStatus {
            installed,
            running: true,
        });
    }

    info!("Skipping Ollama running check.");

    // We'll still do the installation check, but not the 'is_running' test
    let ollama_installed = get_command("ollama")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);

    let ollama_running = false;

    results.insert("ollama".to_string(), ToolStatus {
        installed: ollama_installed,
        running: ollama_running,
    });

    HttpResponse::Ok().json(results)
}

// Add these structs after the existing ones
#[derive(Debug, Serialize, Deserialize)]
struct OpenRouterPricing {
    prompt: f64,
    completion: f64,
}

#[derive(Debug, Serialize, Deserialize)]
struct OpenRouterModel {
    id: String,
    name: String,
    description: String,
    pricing: OpenRouterPricing,
}

#[derive(Debug, Serialize, Deserialize)]
struct OpenRouterModelsResponse {
    data: Vec<OpenRouterModel>,
}

#[derive(Debug, Serialize, Deserialize)]
struct ChatMessage {
    role: String,
    content: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct ChatRequest {
    model: String,
    messages: Vec<ChatMessage>,
}

#[derive(Debug, Serialize, Deserialize)]
struct ChatResponseMessage {
    role: String,
    content: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct ChatResponseChoice {
    message: ChatResponseMessage,
}

#[derive(Debug, Serialize, Deserialize)]
struct ChatResponse {
    id: String,
    choices: Vec<ChatResponseChoice>,
}

// Add these new handler functions before main()

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::Builder::from_env(Env::default().default_filter_or("info"))
        .format_timestamp_secs()
        .init();

    // Create HTTP client for OpenRouter API calls
    let client = Client::new();
    let client_data = web::Data::new(client);

    let local_ip = get_local_ip().unwrap_or("127.0.0.1".to_string());
    info!("Server running on machine with IP: {}", local_ip);
    info!("Starting server at http://127.0.0.1:{}", APP_PORTS[0]);
    
    HttpServer::new(move || {
        App::new()
            .app_data(client_data.clone())
            // Add middleware
            .wrap(Logger::default())
            .wrap(Logger::new("%a %r %s %b %{Referer}i %{User-Agent}i %T"))
            .wrap(
                DefaultHeaders::new()
                    .add(("X-Version", "1.0.0"))
                    .add(("Content-Type", "application/json"))
            )
            // Routes
            .route("/scan/{ip}", web::get().to(scan))
            .route("/discover/{cidr}", web::get().to(discover_hosts))
            .route("/ask", web::post().to(ask_openai))
            .route("/tools", web::get().to(check_tools))
    })
    .bind(format!("127.0.0.1:{}", APP_PORTS[0]))?
    .run()
    .await
}
