use arcis::*;

#[encrypted]
mod access_control {
    use arcis::*;

    pub struct PolicyState {
        /// The minimum payment required to access (e.g., in USDC atomic units)
        pub price: u64,
        /// The expiration timestamp (Unix epoch)
        pub expiry: u64,
        /// The actual AES/Symmetric key for the file (split into u64 chunks)
        /// In reality, a 256-bit key would be [u64; 4]. We use 1 for demo simplicity.
        pub content_key: u64, 
    }

    pub struct UserRequest {
        /// The payment amount provided by the user
        pub payment_amount: u64,
        /// The current network timestamp provided by the validator/clock
        pub current_time: u64,
    }

    pub struct AccessResult {
        /// 1 = Access Granted, 0 = Denied
        pub status: u64,
        /// The decryption key. If denied, this will be 0.
        pub released_key: u64,
    }

    #[instruction]
    pub fn verify_and_release(
        policy_ctxt: Enc<Shared, PolicyState>,
        request_ctxt: Enc<Shared, UserRequest>
    ) -> Enc<Shared, AccessResult> {
        let policy = policy_ctxt.to_arcis();
        let req = request_ctxt.to_arcis();

        // 1. Check Payment Condition (User Payment >= Price)
        let paid_enough = req.payment_amount >= policy.price;

        // 2. Check Time Condition (Current Time < Expiry)
        // If expiry is 0, we assume it's lifetime access (skip check)
        let not_expired = if policy.expiry == 0 {
            1u64 // True
        } else {
            if req.current_time < policy.expiry { 1u64 } else { 0u64 }
        };

        // 3. Aggregate Conditions
        // Both must be true (1 * 1 = 1)
        let access_granted = if paid_enough {
            if not_expired == 1 { 1u64 } else { 0u64 }
        } else {
            0u64
        };

        // 4. Mux: Release Key or Return Zero
        let key_payload = if access_granted == 1 {
            policy.content_key
        } else {
            0u64
        };

        let result = AccessResult {
            status: access_granted,
            released_key: key_payload,
        };

        // The result is encrypted specifically for the Requestor (User).
        // Only they can decrypt the 'released_key' to unlock the IPFS file.
        request_ctxt.owner.from_arcis(result)
    }
}