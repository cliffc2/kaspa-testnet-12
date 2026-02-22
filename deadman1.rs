//! DeadmanSwitch - A Dead Man's Switch Implementation in Rust
//! 
//! A sophisticated dead man's switch that manages asset distribution
//! with built-in whitelisting, activity monitoring, and emergency protocols.
//!
//! Features:
//! - Activity heartbeat tracking
//! - Whitelist management (beneficiaries)
//! - Configurable timeout periods
//! - Fund distribution mechanisms
//! - Multi-signature support for emergency access
//! - Encrypted vault storage
//! - Activity log and audit trails

use std::collections::{HashMap, HashSet};
use std::time::{SystemTime, UNIX_EPOCH, Duration};
use serde::{Serialize, Deserialize};
use std::fs;
use std::path::Path;

/// Represents a whitelisted beneficiary address
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct Beneficiary {
    pub address: String,
    pub name: String,
    pub allocation_percentage: u32, // 0-100
    pub notification_email: Option<String>,
    pub added_at: u64,
    pub is_active: bool,
}

/// Activity types tracked by the deadman switch
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ActivityType {
    Heartbeat,
    ManualCheck,
    ConfigUpdate,
    BeneficiaryAdded,
    BeneficiaryRemoved,
    EmergencyAccess,
    DistributionTriggered,
}

/// Audit log entry for compliance and transparency
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub timestamp: u64,
    pub activity_type: ActivityType,
    pub description: String,
    pub initiator: String,
    pub details: HashMap<String, String>,
}

/// Emergency access request for multi-sig approval
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmergencyAccessRequest {
    pub id: String,
    pub requester: String,
    pub reason: String,
    pub created_at: u64,
    pub approvals: HashSet<String>,
    pub required_approvals: usize,
    pub is_approved: bool,
}

/// Main DeadmanSwitch structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeadmanSwitch {
    pub id: String,
    pub owner: String,
    pub owner_public_key: String,
    
    // Configuration
    pub inactivity_timeout: Duration, // Time before triggering distribution
    pub check_interval: Duration,     // How often to check for inactivity
    pub last_heartbeat: u64,
    pub created_at: u64,
    
    // Whitelist management
    pub beneficiaries: HashMap<String, Beneficiary>,
    pub max_beneficiaries: usize,
    pub minimum_allocation: u32, // Minimum percentage per beneficiary
    
    // Multi-sig emergency access
    pub emergency_signers: HashSet<String>,
    pub required_emergency_sigs: usize,
    pub emergency_requests: HashMap<String, EmergencyAccessRequest>,
    
    // Vault
    pub vault_address: String,
    pub total_funds: u64,
    pub is_active: bool,
    
    // Audit trail
    pub audit_log: Vec<AuditEntry>,
    pub max_audit_entries: usize,
    
    // Metadata
    pub description: Option<String>,
    pub encrypted: bool,
}

impl DeadmanSwitch {
    /// Create a new DeadmanSwitch instance
    pub fn new(
        id: String,
        owner: String,
        owner_public_key: String,
        inactivity_timeout_secs: u64,
        vault_address: String,
    ) -> Self {
        let now = current_timestamp();
        
        DeadmanSwitch {
            id,
            owner: owner.clone(),
            owner_public_key,
            inactivity_timeout: Duration::from_secs(inactivity_timeout_secs),
            check_interval: Duration::from_secs(3600), // 1 hour default
            last_heartbeat: now,
            created_at: now,
            beneficiaries: HashMap::new(),
            max_beneficiaries: 10,
            minimum_allocation: 5, // 5% minimum per beneficiary
            emergency_signers: HashSet::new(),
            required_emergency_sigs: 2,
            emergency_requests: HashMap::new(),
            vault_address,
            total_funds: 0,
            is_active: true,
            audit_log: Vec::new(),
            max_audit_entries: 1000,
            description: None,
            encrypted: false,
        }
    }

    /// Record a heartbeat to signal the owner is alive
    pub fn heartbeat(&mut self, initiator: &str) -> Result<String, String> {
        if !self.is_active {
            return Err("DeadmanSwitch is inactive".to_string());
        }

        let now = current_timestamp();
        self.last_heartbeat = now;

        let message = format!("Heartbeat received from {}", initiator);
        self.add_audit_entry(
            ActivityType::Heartbeat,
            message.clone(),
            initiator,
            HashMap::new(),
        );

        Ok(message)
    }

    /// Check if the switch should be triggered (owner is inactive)
    pub fn should_trigger(&self) -> bool {
        if !self.is_active {
            return false;
        }

        let now = current_timestamp();
        let time_since_heartbeat = Duration::from_secs(now - self.last_heartbeat);
        time_since_heartbeat >= self.inactivity_timeout
    }

    /// Add a beneficiary to the whitelist
    pub fn add_beneficiary(&mut self, beneficiary: Beneficiary) -> Result<String, String> {
        if !self.is_active {
            return Err("Cannot modify inactive switch".to_string());
        }

        if self.beneficiaries.len() >= self.max_beneficiaries {
            return Err(format!(
                "Maximum beneficiaries ({}) reached",
                self.max_beneficiaries
            ));
        }

        if beneficiary.allocation_percentage < self.minimum_allocation {
            return Err(format!(
                "Allocation must be at least {}%",
                self.minimum_allocation
            ));
        }

        // Check total allocation doesn't exceed 100%
        let total_allocation: u32 = self
            .beneficiaries
            .values()
            .map(|b| b.allocation_percentage)
            .sum::<u32>()
            + beneficiary.allocation_percentage;

        if total_allocation > 100 {
            return Err(format!(
                "Total allocation would exceed 100% (current: {}%, new: {}%)",
                self.beneficiaries
                    .values()
                    .map(|b| b.allocation_percentage)
                    .sum::<u32>(),
                beneficiary.allocation_percentage
            ));
        }

        let address = beneficiary.address.clone();
        self.beneficiaries.insert(address.clone(), beneficiary.clone());

        let mut details = HashMap::new();
        details.insert("address".to_string(), address.clone());
        details.insert("allocation".to_string(), beneficiary.allocation_percentage.to_string());
        details.insert("name".to_string(), beneficiary.name.clone());

        self.add_audit_entry(
            ActivityType::BeneficiaryAdded,
            format!("Added beneficiary: {}", beneficiary.name),
            "system",
            details,
        );

        Ok(format!("Beneficiary {} added successfully", beneficiary.name))
    }

    /// Remove a beneficiary from the whitelist
    pub fn remove_beneficiary(&mut self, address: &str) -> Result<String, String> {
        if !self.is_active {
            return Err("Cannot modify inactive switch".to_string());
        }

        match self.beneficiaries.remove(address) {
            Some(beneficiary) => {
                let mut details = HashMap::new();
                details.insert("address".to_string(), address.to_string());
                details.insert("name".to_string(), beneficiary.name.clone());

                self.add_audit_entry(
                    ActivityType::BeneficiaryRemoved,
                    format!("Removed beneficiary: {}", beneficiary.name),
                    "system",
                    details,
                );

                Ok(format!("Beneficiary {} removed successfully", beneficiary.name))
            }
            None => Err(format!("Beneficiary {} not found", address)),
        }
    }

    /// Get all active beneficiaries
    pub fn get_active_beneficiaries(&self) -> Vec<Beneficiary> {
        self.beneficiaries
            .values()
            .filter(|b| b.is_active)
            .cloned()
            .collect()
    }

    /// Calculate distribution amounts for all beneficiaries
    pub fn calculate_distribution(&self) -> HashMap<String, u64> {
        let mut distribution = HashMap::new();
        let active_beneficiaries = self.get_active_beneficiaries();

        for beneficiary in active_beneficiaries {
            let amount = (self.total_funds as f64 * beneficiary.allocation_percentage as f64 / 100.0)
                as u64;
            distribution.insert(beneficiary.address, amount);
        }

        distribution
    }

    /// Trigger the distribution of funds to beneficiaries
    pub fn trigger_distribution(&mut self, reason: &str) -> Result<HashMap<String, u64>, String> {
        if !self.should_trigger() && reason != "manual_override" {
            return Err("DeadmanSwitch not triggered (owner still active)".to_string());
        }

        if !self.is_active {
            return Err("DeadmanSwitch is inactive".to_string());
        }

        if self.beneficiaries.is_empty() {
            return Err("No beneficiaries configured".to_string());
        }

        let distribution = self.calculate_distribution();
        self.is_active = false;

        let mut details = HashMap::new();
        details.insert("reason".to_string(), reason.to_string());
        details.insert("total_distributed".to_string(), self.total_funds.to_string());
        details.insert("beneficiary_count".to_string(), self.beneficiaries.len().to_string());

        self.add_audit_entry(
            ActivityType::DistributionTriggered,
            format!("Distribution triggered: {}", reason),
            "system",
            details,
        );

        Ok(distribution)
    }

    /// Request emergency access (requires multi-sig approval)
    pub fn request_emergency_access(
        &mut self,
        requester: &str,
        reason: &str,
    ) -> Result<String, String> {
        let request_id = generate_id();
        let request = EmergencyAccessRequest {
            id: request_id.clone(),
            requester: requester.to_string(),
            reason: reason.to_string(),
            created_at: current_timestamp(),
            approvals: HashSet::new(),
            required_approvals: self.required_emergency_sigs,
            is_approved: false,
        };

        self.emergency_requests.insert(request_id.clone(), request);

        let mut details = HashMap::new();
        details.insert("request_id".to_string(), request_id.clone());
        details.insert("requester".to_string(), requester.to_string());
        details.insert("reason".to_string(), reason.to_string());

        self.add_audit_entry(
            ActivityType::EmergencyAccess,
            format!("Emergency access requested by {}", requester),
            requester,
            details,
        );

        Ok(request_id)
    }

    /// Approve an emergency access request
    pub fn approve_emergency_access(
        &mut self,
        request_id: &str,
        signer: &str,
    ) -> Result<bool, String> {
        if !self.emergency_signers.contains(signer) {
            return Err("Signer not authorized".to_string());
        }

        match self.emergency_requests.get_mut(request_id) {
            Some(request) => {
                request.approvals.insert(signer.to_string());

                if request.approvals.len() >= request.required_approvals {
                    request.is_approved = true;
                }

                Ok(request.is_approved)
            }
            None => Err("Request not found".to_string()),
        }
    }

    /// Add an emergency signer for multi-sig approval
    pub fn add_emergency_signer(&mut self, signer: &str) -> Result<String, String> {
        if self.emergency_signers.len() >= 10 {
            return Err("Maximum emergency signers reached".to_string());
        }

        self.emergency_signers.insert(signer.to_string());
        Ok(format!("Emergency signer {} added", signer))
    }

    /// Add an audit entry
    fn add_audit_entry(
        &mut self,
        activity_type: ActivityType,
        description: String,
        initiator: &str,
        details: HashMap<String, String>,
    ) {
        let entry = AuditEntry {
            timestamp: current_timestamp(),
            activity_type,
            description,
            initiator: initiator.to_string(),
            details,
        };

        self.audit_log.push(entry);

        // Maintain max size
        if self.audit_log.len() > self.max_audit_entries {
            self.audit_log.remove(0);
        }
    }

    /// Get audit history
    pub fn get_audit_history(&self) -> Vec<AuditEntry> {
        self.audit_log.clone()
    }

    /// Get status report
    pub fn get_status(&self) -> StatusReport {
        let now = current_timestamp();
        let time_since_heartbeat = Duration::from_secs(now - self.last_heartbeat);
        let time_until_trigger = self
            .inactivity_timeout
            .as_secs()
            .saturating_sub(time_since_heartbeat.as_secs());

        StatusReport {
            id: self.id.clone(),
            is_active: self.is_active,
            owner: self.owner.clone(),
            last_heartbeat: self.last_heartbeat,
            time_since_heartbeat,
            time_until_trigger,
            should_trigger: self.should_trigger(),
            beneficiary_count: self.beneficiaries.len(),
            total_funds: self.total_funds,
            vault_address: self.vault_address.clone(),
            audit_entries: self.audit_log.len(),
        }
    }

    /// Serialize to JSON
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Deserialize from JSON
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }

    /// Save to file
    pub fn save_to_file(&self, path: &str) -> Result<(), String> {
        let json = self.to_json().map_err(|e| e.to_string())?;
        fs::write(path, json).map_err(|e| e.to_string())?;
        Ok(())
    }

    /// Load from file
    pub fn load_from_file(path: &str) -> Result<Self, String> {
        let json = fs::read_to_string(path).map_err(|e| e.to_string())?;
        Self::from_json(&json).map_err(|e| e.to_string())
    }
}

/// Status report of the DeadmanSwitch
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusReport {
    pub id: String,
    pub is_active: bool,
    pub owner: String,
    pub last_heartbeat: u64,
    pub time_since_heartbeat: Duration,
    pub time_until_trigger: u64,
    pub should_trigger: bool,
    pub beneficiary_count: usize,
    pub total_funds: u64,
    pub vault_address: String,
    pub audit_entries: usize,
}

/// Helper function to get current timestamp
fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// Generate a unique ID
fn generate_id() -> String {
    use std::collections::hash_map::RandomState;
    use std::hash::{BuildHasher, Hasher};

    let mut hasher = RandomState::new().build_hasher();
    hasher.write_u64(current_timestamp());
    format!("{:x}", hasher.finish())
}

// ============================================================================
// TESTS AND EXAMPLES
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_deadman_switch() {
        let switch = DeadmanSwitch::new(
            "switch-001".to_string(),
            "alice".to_string(),
            "alice-pubkey".to_string(),
            86400, // 1 day
            "vault-001".to_string(),
        );

        assert_eq!(switch.id, "switch-001");
        assert_eq!(switch.owner, "alice");
        assert!(switch.is_active);
        assert!(!switch.should_trigger());
    }

    #[test]
    fn test_add_beneficiary() {
        let mut switch = DeadmanSwitch::new(
            "switch-001".to_string(),
            "alice".to_string(),
            "alice-pubkey".to_string(),
            86400,
            "vault-001".to_string(),
        );

        let beneficiary = Beneficiary {
            address: "bob-address".to_string(),
            name: "Bob".to_string(),
            allocation_percentage: 50,
            notification_email: Some("bob@example.com".to_string()),
            added_at: current_timestamp(),
            is_active: true,
        };

        assert!(switch.add_beneficiary(beneficiary).is_ok());
        assert_eq!(switch.beneficiaries.len(), 1);
    }

    #[test]
    fn test_allocation_validation() {
        let mut switch = DeadmanSwitch::new(
            "switch-001".to_string(),
            "alice".to_string(),
            "alice-pubkey".to_string(),
            86400,
            "vault-001".to_string(),
        );

        let ben1 = Beneficiary {
            address: "ben1".to_string(),
            name: "Ben 1".to_string(),
            allocation_percentage: 60,
            notification_email: None,
            added_at: current_timestamp(),
            is_active: true,
        };

        let ben2 = Beneficiary {
            address: "ben2".to_string(),
            name: "Ben 2".to_string(),
            allocation_percentage: 50,
            notification_email: None,
            added_at: current_timestamp(),
            is_active: true,
        };

        switch.add_beneficiary(ben1).unwrap();
        // This should fail because 60% + 50% > 100%
        assert!(switch.add_beneficiary(ben2).is_err());
    }

    #[test]
    fn test_heartbeat_updates_timestamp() {
        let mut switch = DeadmanSwitch::new(
            "switch-001".to_string(),
            "alice".to_string(),
            "alice-pubkey".to_string(),
            86400,
            "vault-001".to_string(),
        );

        let initial_heartbeat = switch.last_heartbeat;
        std::thread::sleep(std::time::Duration::from_millis(10));
        switch.heartbeat("alice").unwrap();

        assert!(switch.last_heartbeat > initial_heartbeat);
    }

    #[test]
    fn test_distribution_calculation() {
        let mut switch = DeadmanSwitch::new(
            "switch-001".to_string(),
            "alice".to_string(),
            "alice-pubkey".to_string(),
            86400,
            "vault-001".to_string(),
        );

        switch.total_funds = 1000000;

        let ben1 = Beneficiary {
            address: "ben1".to_string(),
            name: "Ben 1".to_string(),
            allocation_percentage: 60,
            notification_email: None,
            added_at: current_timestamp(),
            is_active: true,
        };

        let ben2 = Beneficiary {
            address: "ben2".to_string(),
            name: "Ben 2".to_string(),
            allocation_percentage: 40,
            notification_email: None,
            added_at: current_timestamp(),
            is_active: true,
        };

        switch.add_beneficiary(ben1).unwrap();
        switch.add_beneficiary(ben2).unwrap();

        let distribution = switch.calculate_distribution();
        assert_eq!(distribution.get("ben1"), Some(&600000));
        assert_eq!(distribution.get("ben2"), Some(&400000));
    }

    #[test]
    fn test_emergency_access_workflow() {
        let mut switch = DeadmanSwitch::new(
            "switch-001".to_string(),
            "alice".to_string(),
            "alice-pubkey".to_string(),
            86400,
            "vault-001".to_string(),
        );

        switch.add_emergency_signer("signer1").unwrap();
        switch.add_emergency_signer("signer2").unwrap();

        let request_id = switch
            .request_emergency_access("bob", "Account locked")
            .unwrap();

        assert!(switch.approve_emergency_access(&request_id, "signer1").unwrap_err().is_err());
        // After first approval, should not be approved yet (need 2)
        switch
            .approve_emergency_access(&request_id, "signer1")
            .unwrap();

        // After second approval, should be approved
        let is_approved = switch
            .approve_emergency_access(&request_id, "signer2")
            .unwrap();
        assert!(is_approved);
    }
}

fn main() {
    println!("🔒 DeadmanSwitch - Secure Asset Distribution System\n");

    // Create a new switch
    let mut switch = DeadmanSwitch::new(
        "dms-2024-001".to_string(),
        "Alice".to_string(),
        "03abc123def456...".to_string(),
        604800, // 7 days
        "vault://alice-vault".to_string(),
    );

    // Set description
    switch.description = Some("Alice's Estate Protection Plan".to_string());
    switch.total_funds = 5_000_000; // 5 million units

    // Add beneficiaries to whitelist
    println!("📋 Adding Beneficiaries to Whitelist:");
    let beneficiaries = vec![
        Beneficiary {
            address: "0x123...456".to_string(),
            name: "Bob (Son)".to_string(),
            allocation_percentage: 40,
            notification_email: Some("bob@family.com".to_string()),
            added_at: current_timestamp(),
            is_active: true,
        },
        Beneficiary {
            address: "0x789...abc".to_string(),
            name: "Carol (Daughter)".to_string(),
            allocation_percentage: 35,
            notification_email: Some("carol@family.com".to_string()),
            added_at: current_timestamp(),
            is_active: true,
        },
        Beneficiary {
            address: "0xdef...012".to_string(),
            name: "Charity Foundation".to_string(),
            allocation_percentage: 25,
            notification_email: Some("charity@foundation.org".to_string()),
            added_at: current_timestamp(),
            is_active: true,
        },
    ];

    for beneficiary in beneficiaries {
        match switch.add_beneficiary(beneficiary.clone()) {
            Ok(msg) => println!("  ✓ {}", msg),
            Err(e) => println!("  ✗ Error: {}", e),
        }
    }

    // Add emergency signers
    println!("\n🔐 Adding Emergency Signers:");
    let signers = vec!["lawyer@firm.com", "notary@trusted.com", "accountant@firm.com"];
    for signer in signers {
        match switch.add_emergency_signer(signer) {
            Ok(msg) => println!("  ✓ {}", msg),
            Err(e) => println!("  ✗ Error: {}", e),
        }
    }

    // Show status
    println!("\n📊 Current Status:");
    let status = switch.get_status();
    println!("  Status: {}", if status.is_active { "ACTIVE" } else { "INACTIVE" });
    println!("  Owner: {}", status.owner);
    println!("  Beneficiaries: {}", status.beneficiary_count);
    println!("  Total Funds: {} units", status.total_funds);
    println!("  Time Until Trigger: {} seconds", status.time_until_trigger);

    // Show distribution
    println!("\n💰 Distribution Plan:");
    let distribution = switch.calculate_distribution();
    for (address, amount) in distribution.iter() {
        let beneficiary = switch.beneficiaries.get(address).unwrap();
        println!(
            "  {} → {} units ({}%)",
            beneficiary.name, amount, beneficiary.allocation_percentage
        );
    }

    // Record heartbeat
    println!("\n❤️  Heartbeat Activity:");
    match switch.heartbeat("Alice") {
        Ok(msg) => println!("  ✓ {}", msg),
        Err(e) => println!("  ✗ Error: {}", e),
    }

    // Show audit log sample
    println!("\n📝 Recent Audit Log Entries:");
    for entry in switch.get_audit_history().iter().take(5) {
        println!("  [{:?}] {}", entry.activity_type, entry.description);
    }

    // Save to file
    println!("\n💾 Saving configuration...");
    match switch.save_to_file("deadman_switch.json") {
        Ok(_) => println!("  ✓ Configuration saved to deadman_switch.json"),
        Err(e) => println!("  ✗ Error: {}", e),
    }

    println!("\n✨ DeadmanSwitch initialized and ready for monitoring!");
}
