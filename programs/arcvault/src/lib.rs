use anchor_lang::prelude::*;
use arcium_anchor::prelude::*;

const COMP_DEF_OFFSET_ACCESS: u32 = comp_def_offset("verify_and_release");

declare_id!("6EzpvoFyxWd51t2yAn4cvBc3JKo6h9QAaVQb3Rb1MB87");

#[arcium_program]
pub mod arcvault {
    use super::*;

    pub fn init_config(ctx: Context<InitConfig>) -> Result<()> {
        init_comp_def(ctx.accounts, None, None)?;
        Ok(())
    }

    /// [Create] Mint a new Data Vault
    /// The content creator encrypts their file key and policy, storing it on-chain.
    pub fn create_vault(
        ctx: Context<CreateVault>,
        encrypted_price: [u8; 32],
        encrypted_expiry: [u8; 32],
        encrypted_key: [u8; 32],
        metadata_cid: String, // IPFS CID for public metadata
    ) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        vault.authority = ctx.accounts.authority.key();
        vault.metadata_cid = metadata_cid;
        
        // Store encrypted policy state
        vault.enc_price = encrypted_price;
        vault.enc_expiry = encrypted_expiry;
        vault.enc_content_key = encrypted_key;
        
        msg!("Data Vault Created. Key is secret-shared on Arcium.");
        Ok(())
    }

    /// [Access] Request to decrypt the file
    /// User proves payment/time. Arcium verifies and returns the key off-chain.
    pub fn request_access(
        ctx: Context<RequestAccess>,
        computation_offset: u64,
        enc_payment: [u8; 32],      // Encrypted payment proof/amount
        enc_timestamp: [u8; 32],    // Encrypted current time
        pubkey: [u8; 32],
        nonce: u128,
    ) -> Result<()> {
        let vault = &ctx.accounts.vault;
        ctx.accounts.sign_pda_account.bump = ctx.bumps.sign_pda_account;
        
        let args = ArgBuilder::new()
            .x25519_pubkey(pubkey)
            .plaintext_u128(nonce)
            // Policy State (From Chain)
            .encrypted_u64(vault.enc_price)
            .encrypted_u64(vault.enc_expiry)
            .encrypted_u64(vault.enc_content_key)
            // User Request (From Args)
            .encrypted_u64(enc_payment)
            .encrypted_u64(enc_timestamp)
            .build();

        queue_computation(
            ctx.accounts,
            computation_offset,
            args,
            vec![AccessCallback::callback_ix(
                computation_offset,
                &ctx.accounts.mxe_account,
                &[]
            )?],
            1,
            0,
        )?;
        Ok(())
    }

    #[arcium_callback(encrypted_ix = "verify_and_release")]
    pub fn verify_and_release_callback(
        ctx: Context<AccessCallback>,
        output: SignedComputationOutputs<VerifyAndReleaseOutput>,
    ) -> Result<()> {
        let o = match output.verify_output(&ctx.accounts.cluster_account, &ctx.accounts.computation_account) {
            Ok(VerifyAndReleaseOutput { field_0 }) => field_0,
            Err(_) => return Err(ErrorCode::AbortedComputation.into()),
        };

        // Result: { status, released_key }
        // We only check the status bit on-chain for event emission.
        // The `released_key` is encrypted for the user and cannot be read here.
        let status_bytes: [u8; 8] = o.ciphertexts[0][0..8].try_into().unwrap();
        let granted = u64::from_le_bytes(status_bytes) == 1;

        if granted {
            msg!("✅ Access Granted by Protocol. Key delivered to user.");
        } else {
            msg!("⛔ Access Denied. Policy conditions not met.");
        }

        emit!(AccessAttemptEvent {
            vault: ctx.accounts.vault.key(),
            success: granted,
            timestamp: Clock::get()?.unix_timestamp,
        });
        Ok(())
    }
}

// --- Accounts ---

#[derive(Accounts)]
pub struct CreateVault<'info> {
    #[account(
        init, 
        payer = authority, 
        space = 8 + 32 + 40 + (32 * 3) + 100, // Padding for string
        seeds = [b"vault", authority.key().as_ref()],
        bump
    )]
    pub vault: Account<'info, DataVault>,
    #[account(mut)]
    pub authority: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[account]
pub struct DataVault {
    pub authority: Pubkey,
    pub metadata_cid: String,
    // Encrypted Policy
    pub enc_price: [u8; 32],
    pub enc_expiry: [u8; 32],
    pub enc_content_key: [u8; 32], // The "Ghost Key"
}

#[queue_computation_accounts("verify_and_release", payer)]
#[derive(Accounts)]
#[instruction(computation_offset: u64)]
pub struct RequestAccess<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,
    pub vault: Account<'info, DataVault>,
    
    #[account(init_if_needed, space = 9, payer = payer, seeds = [&SIGN_PDA_SEED], bump, address = derive_sign_pda!())]
    pub sign_pda_account: Account<'info, ArciumSignerAccount>,
    #[account(address = derive_mxe_pda!())]
    pub mxe_account: Box<Account<'info, MXEAccount>>,
    #[account(mut, address = derive_mempool_pda!(mxe_account, ErrorCode::ClusterNotSet))]
    /// CHECK: Mempool
    pub mempool_account: UncheckedAccount<'info>,
    #[account(mut, address = derive_execpool_pda!(mxe_account, ErrorCode::ClusterNotSet))]
    /// CHECK: Execpool
    pub executing_pool: UncheckedAccount<'info>,
    #[account(mut, address = derive_comp_pda!(computation_offset, mxe_account, ErrorCode::ClusterNotSet))]
    /// CHECK: Comp
    pub computation_account: UncheckedAccount<'info>,
    #[account(address = derive_comp_def_pda!(COMP_DEF_OFFSET_ACCESS))]
    pub comp_def_account: Account<'info, ComputationDefinitionAccount>,
    #[account(mut, address = derive_cluster_pda!(mxe_account, ErrorCode::ClusterNotSet))]
    pub cluster_account: Account<'info, Cluster>,
    #[account(mut, address = ARCIUM_FEE_POOL_ACCOUNT_ADDRESS)]
    pub pool_account: Account<'info, FeePool>,
    #[account(mut, address = ARCIUM_CLOCK_ACCOUNT_ADDRESS)]
    pub clock_account: Account<'info, ClockAccount>,
    pub system_program: Program<'info, System>,
    pub arcium_program: Program<'info, Arcium>,
}

#[callback_accounts("verify_and_release")]
#[derive(Accounts)]
pub struct AccessCallback<'info> {
    pub arcium_program: Program<'info, Arcium>,
    #[account(address = derive_comp_def_pda!(COMP_DEF_OFFSET_ACCESS))]
    pub comp_def_account: Account<'info, ComputationDefinitionAccount>,
    #[account(address = derive_mxe_pda!())]
    pub mxe_account: Box<Account<'info, MXEAccount>>,
    /// CHECK: Comp
    pub computation_account: UncheckedAccount<'info>,
    #[account(address = derive_cluster_pda!(mxe_account, ErrorCode::ClusterNotSet))]
    pub cluster_account: Account<'info, Cluster>,
    pub vault: Account<'info, DataVault>, // For event emission context
    #[account(address = ::anchor_lang::solana_program::sysvar::instructions::ID)]
    /// CHECK: Sysvar
    pub instructions_sysvar: AccountInfo<'info>,
}

#[init_computation_definition_accounts("verify_and_release", payer)]
#[derive(Accounts)]
pub struct InitConfig<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,
    #[account(mut, address = derive_mxe_pda!())]
    pub mxe_account: Box<Account<'info, MXEAccount>>,
    #[account(mut)]
    /// CHECK: Def
    pub comp_def_account: UncheckedAccount<'info>,
    #[account(mut, address = derive_mxe_lut_pda!(mxe_account.lut_offset_slot))]
    /// CHECK: Lut
    pub address_lookup_table: UncheckedAccount<'info>,
    #[account(address = LUT_PROGRAM_ID)]
    /// CHECK: Lut Prog
    pub lut_program: UncheckedAccount<'info>,
    pub arcium_program: Program<'info, Arcium>,
    pub system_program: Program<'info, System>,
}

#[event]
pub struct AccessAttemptEvent {
    pub vault: Pubkey,
    pub success: bool,
    pub timestamp: i64,
}

#[error_code]
pub enum ErrorCode {
    #[msg("Aborted")] AbortedComputation,
    #[msg("No Cluster")] ClusterNotSet,
}