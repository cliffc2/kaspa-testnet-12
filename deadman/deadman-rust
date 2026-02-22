use silverscript_lang::compiler::{compile_contract, CompileOptions};
use silverscript_lang::ast::Expr;

fn compile_dead_man_switch(
    owner_pubkey: Vec<u8>,
    beneficiary_pubkey: Vec<u8>,
    check_in_period: i64,
) -> Result<CompiledContract, Box<dyn std::error::Error>> {
    let source = r#"
        pragma silverscript ^0.1.0;

        contract DeadManSwitch(pubkey owner, pubkey beneficiary, int checkInPeriod) {
            int lastCheckIn = tx.time;
            
            entrypoint function checkIn(sig ownerSig) {
                require(checkSig(ownerSig, owner));
                validateOutputState(0, { lastCheckIn: tx.time });
            }
            
            entrypoint function claimIfDeadman() {
                int timeSinceCheckIn = tx.time - lastCheckIn;
                require(timeSinceCheckIn >= checkInPeriod);
                
                byte [34] beneficiaryScript = new ScriptPubKeyP2PK(beneficiary);
                require(tx.outputs [0].scriptPubKey == beneficiaryScript);
                require(tx.outputs [0].value >= tx.inputs[this.activeInputIndex].value - 1000);
            }
            
            entrypoint function ownerReclaim(sig ownerSig) {
                require(checkSig(ownerSig, owner));
                
                byte [34] ownerScript = new ScriptPubKeyP2PK(owner);
                require(tx.outputs [0].scriptPubKey == ownerScript);
            }
        }
    "#;

    let constructor_args = vec![
        Expr::Bytes(owner_pubkey),
        Expr::Bytes(beneficiary_pubkey),
        Expr::Int(check_in_period),
    ];

    let compiled = compile_contract(source, &constructor_args, CompileOptions::default())?;
    
    Ok(compiled)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Example: 30-day check-in period
    let owner_pk = vec![3u8; 32];
    let beneficiary_pk = vec![4u8; 32];
    let thirty_days = 30 * 24 * 60 * 60; // seconds
    
    let compiled = compile_dead_man_switch(owner_pk, beneficiary_pk, thirty_days)?;
    
    println
