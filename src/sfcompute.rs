// SPDX-FileCopyrightText: 2025 SF Compute <hi@sfcompute.com>
// SPDX-License-Identifier: MPL-2.0

//! SF Compute infrastructure integration features
//! 
//! This module provides integration with SF Compute's infrastructure tools:
//! - Doppler secrets management
//! - Tailscale OAuth integration  
//! - GPU cluster management
//! - Infrastructure telemetry

use log::{debug, info, warn};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::env;
use std::process::Command;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SfComputeError {
    #[error("Doppler CLI not found or not logged in")]
    DopplerNotAvailable,
    #[error("Failed to retrieve secret from Doppler: {0}")]
    DopplerSecretError(String),
    #[error("Tailscale OAuth error: {0}")]
    TailscaleError(String),
    #[error("HTTP request error: {0}")]
    HttpError(#[from] reqwest::Error),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TailscaleAuthKey {
    pub key: String,
    pub description: String,
    pub expires: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TailscaleAuthRequest {
    pub capabilities: TailscaleCapabilities,
    #[serde(rename = "expirySeconds")]
    pub expiry_seconds: Option<u64>,
    pub description: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TailscaleCapabilities {
    pub devices: TailscaleDevices,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TailscaleDevices {
    pub create: TailscaleCreate,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TailscaleCreate {
    pub reusable: bool,
    pub ephemeral: bool,
    pub preauthorized: bool,
    pub tags: Vec<String>,
}

/// SF Compute infrastructure configuration
#[derive(Debug, Clone)]
pub struct InfraConfig {
    /// Doppler project for secrets
    pub doppler_project: String,
    /// Doppler config environment
    pub doppler_config: String,
    /// Default Tailscale tags for deployed nodes
    pub tailscale_tags: Vec<String>,
    /// Enable infrastructure telemetry
    pub telemetry_enabled: bool,
}

impl Default for InfraConfig {
    fn default() -> Self {
        Self {
            doppler_project: "metal-boot".to_string(),
            doppler_config: "prd".to_string(),
            tailscale_tags: vec!["tag:infractl".to_string()],
            telemetry_enabled: true,
        }
    }
}

/// Retrieve secrets from Doppler
pub fn get_doppler_secret(project: &str, config: &str, secret_name: &str) -> Result<String, SfComputeError> {
    debug!("Retrieving secret '{}' from Doppler project '{}'", secret_name, project);
    
    // Check if doppler CLI is available
    let doppler_check = Command::new("doppler")
        .arg("me")
        .output();
    
    if doppler_check.is_err() {
        return Err(SfComputeError::DopplerNotAvailable);
    }
    
    let output = Command::new("doppler")
        .args(&["secrets", "get", secret_name])
        .args(&["--project", project])
        .args(&["--config", config])
        .arg("--plain")
        .output()
        .map_err(|e| SfComputeError::DopplerSecretError(e.to_string()))?;
    
    if !output.status.success() {
        let error_msg = String::from_utf8_lossy(&output.stderr);
        return Err(SfComputeError::DopplerSecretError(error_msg.to_string()));
    }
    
    let secret = String::from_utf8_lossy(&output.stdout).trim().to_string();
    debug!("Successfully retrieved secret from Doppler");
    Ok(secret)
}

/// Create ephemeral Tailscale auth key using OAuth
pub async fn create_tailscale_auth_key(
    client_id: &str,
    client_secret: &str,
    hostname: &str,
    tags: &[String],
) -> Result<String, SfComputeError> {
    info!("Creating ephemeral Tailscale auth key for hostname: {}", hostname);
    
    let client = reqwest::Client::new();
    
    // Get OAuth token
    let auth_params = [
        ("grant_type", "client_credentials"),
        ("scope", "devices"),
    ];
    
    let auth_header = base64::encode(format!("{}:{}", client_id, client_secret));
    
    let token_response = client
        .post("https://api.tailscale.com/api/v2/oauth/token")
        .header("Authorization", format!("Basic {}", auth_header))
        .header("Content-Type", "application/x-www-form-urlencoded")
        .form(&auth_params)
        .send()
        .await?;
    
    if !token_response.status().is_success() {
        let error_text = token_response.text().await?;
        return Err(SfComputeError::TailscaleError(format!("OAuth token request failed: {}", error_text)));
    }
    
    let token_data: serde_json::Value = token_response.json().await?;
    let access_token = token_data["access_token"]
        .as_str()
        .ok_or_else(|| SfComputeError::TailscaleError("No access token in OAuth response".to_string()))?;
    
    // Create auth key
    let auth_request = TailscaleAuthRequest {
        capabilities: TailscaleCapabilities {
            devices: TailscaleDevices {
                create: TailscaleCreate {
                    reusable: false,
                    ephemeral: true,
                    preauthorized: true,
                    tags: tags.to_vec(),
                },
            },
        },
        expiry_seconds: Some(3600), // 1 hour
        description: format!("infractl auto-join for {}", hostname),
    };
    
    let key_response = client
        .post("https://api.tailscale.com/api/v2/tailnet/-/keys")
        .header("Authorization", format!("Bearer {}", access_token))
        .header("Content-Type", "application/json")
        .json(&auth_request)
        .send()
        .await?;
    
    if !key_response.status().is_success() {
        let error_text = key_response.text().await?;
        return Err(SfComputeError::TailscaleError(format!("Auth key creation failed: {}", error_text)));
    }
    
    let key_data: TailscaleAuthKey = key_response.json().await?;
    info!("Successfully created ephemeral Tailscale auth key");
    Ok(key_data.key)
}

/// Auto-configure Tailscale OAuth environment variables from Doppler
pub fn setup_tailscale_oauth_env(config: &InfraConfig) -> Result<(), SfComputeError> {
    if env::var("METAL_BOOT_TAILSCALE_CLIENT_ID").is_ok() && env::var("METAL_BOOT_TAILSCALE_CLIENT_SECRET").is_ok() {
        debug!("Tailscale OAuth environment variables already set");
        return Ok(());
    }
    
    info!("Setting up Tailscale OAuth environment from Doppler");
    
    let client_id = get_doppler_secret(&config.doppler_project, &config.doppler_config, "METAL_BOOT_TAILSCALE_CLIENT_ID")?;
    let client_secret = get_doppler_secret(&config.doppler_project, &config.doppler_config, "METAL_BOOT_TAILSCALE_CLIENT_SECRET")?;
    
    env::set_var("METAL_BOOT_TAILSCALE_CLIENT_ID", client_id);
    env::set_var("METAL_BOOT_TAILSCALE_CLIENT_SECRET", client_secret);
    
    info!("Tailscale OAuth environment configured successfully");
    Ok(())
}

/// Send deployment telemetry (if enabled)
pub async fn send_deployment_telemetry(
    node_name: &str,
    profile_name: &str,
    success: bool,
    duration_ms: u64,
    config: &InfraConfig,
) -> Result<(), SfComputeError> {
    if !config.telemetry_enabled {
        return Ok(());
    }
    
    debug!("Sending deployment telemetry for {}:{}", node_name, profile_name);
    
    let telemetry_data = serde_json::json!({
        "node": node_name,
        "profile": profile_name,
        "success": success,
        "duration_ms": duration_ms,
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "tool": "infractl-deploy",
        "version": env!("CARGO_PKG_VERSION")
    });
    
    // Note: In a real implementation, you'd send this to your telemetry endpoint
    // For now, just log it
    info!("Deployment telemetry: {}", telemetry_data);
    
    Ok(())
}

/// Get infrastructure configuration from environment
pub fn get_infra_config() -> InfraConfig {
    InfraConfig {
        doppler_project: env::var("INFRACTL_DOPPLER_PROJECT").unwrap_or_else(|_| "metal-boot".to_string()),
        doppler_config: env::var("INFRACTL_DOPPLER_CONFIG").unwrap_or_else(|_| "prd".to_string()),
        tailscale_tags: env::var("INFRACTL_TAILSCALE_TAGS")
            .unwrap_or_else(|_| "tag:infractl".to_string())
            .split(',')
            .map(|s| s.trim().to_string())
            .collect(),
        telemetry_enabled: env::var("INFRACTL_TELEMETRY_ENABLED")
            .map(|v| v.to_lowercase() == "true")
            .unwrap_or(true),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_infra_config_default() {
        let config = InfraConfig::default();
        assert_eq!(config.doppler_project, "metal-boot");
        assert_eq!(config.doppler_config, "prd");
        assert_eq!(config.tailscale_tags, vec!["tag:infractl"]);
        assert!(config.telemetry_enabled);
    }

    #[test]
    fn test_get_infra_config_from_env() {
        env::set_var("INFRACTL_DOPPLER_PROJECT", "test-project");
        env::set_var("INFRACTL_TAILSCALE_TAGS", "tag:test,tag:gpu");
        env::set_var("INFRACTL_TELEMETRY_ENABLED", "false");
        
        let config = get_infra_config();
        assert_eq!(config.doppler_project, "test-project");
        assert_eq!(config.tailscale_tags, vec!["tag:test", "tag:gpu"]);
        assert!(!config.telemetry_enabled);
        
        // Clean up
        env::remove_var("INFRACTL_DOPPLER_PROJECT");
        env::remove_var("INFRACTL_TAILSCALE_TAGS");
        env::remove_var("INFRACTL_TELEMETRY_ENABLED");
    }
}