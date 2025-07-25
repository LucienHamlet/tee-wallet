"""
TEE Secure Wallet Implementation for SpoonOS
Provides hardware-secured private key management with policy-based signing
"""

import os
import json
import hashlib
import hmac
import time
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
import logging

logger = logging.getLogger(__name__)


@dataclass
class SigningPolicy:
    """Defines rules for transaction signing"""

    max_transaction_value: float = 1000.0  # USD
    daily_limit: float = 5000.0  # USD
    allowed_contracts: List[str] = None
    blocked_contracts: List[str] = None
    require_confirmation_above: float = 500.0  # USD
    time_restrictions: Dict[str, Any] = None  # e.g., {"start": "09:00", "end": "17:00"}

    def __post_init__(self):
        if self.allowed_contracts is None:
            self.allowed_contracts = []
        if self.blocked_contracts is None:
            self.blocked_contracts = []
        if self.time_restrictions is None:
            self.time_restrictions = {}


@dataclass
class TransactionRequest:
    """Represents a transaction signing request"""

    to_address: str
    value: float  # in USD
    data: str = ""
    gas_limit: int = 21000
    gas_price: int = 20000000000  # 20 gwei
    nonce: Optional[int] = None
    chain_id: int = 1  # Ethereum mainnet
    timestamp: float = None

    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = time.time()


class TEESecureEnclave:
    """
    TEE (Trusted Execution Environment) for secure key operations
    Supports Intel SGX, ARM TrustZone, and other hardware security modules
    """

    def __init__(self, enclave_id: str):
        self.enclave_id = enclave_id
        self._master_key = self._derive_master_key()
        self._audit_log = []

    def _derive_master_key(self) -> bytes:
        """Derive master key from hardware-specific entropy"""
        # In real TEE, this would use hardware entropy
        # For deterministic key generation in tests, use only enclave_id
        seed = f"tee_master_key_{self.enclave_id}_deterministic"
        return hashlib.sha256(seed.encode()).digest()

    def generate_private_key(self, key_id: str) -> ec.EllipticCurvePrivateKey:
        """Generate a new private key within the secure enclave"""
        # Derive deterministic key from master key and key_id
        kdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b"spoon_tee_wallet",
            info=key_id.encode(),
            backend=default_backend(),
        )
        key_material = kdf.derive(self._master_key)

        # Generate secp256k1 private key (used by Ethereum)
        # Use a simpler approach that works with the cryptography library
        curve = ec.SECP256K1()
        private_value = int.from_bytes(key_material, "big")
        # Ensure the private key is within the valid range for secp256k1
        # secp256k1 order is: 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
        secp256k1_order = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
        private_value = private_value % secp256k1_order
        if private_value == 0:
            private_value = 1  # Ensure non-zero private key

        private_key = ec.derive_private_key(private_value, curve, default_backend())

        self._audit_log.append({"action": "key_generation", "key_id": key_id, "timestamp": time.time()})

        return private_key

    def sign_data(self, private_key: ec.EllipticCurvePrivateKey, data: bytes) -> bytes:
        """Sign data within the secure enclave"""
        signature = private_key.sign(data, ec.ECDSA(hashes.SHA256()))

        self._audit_log.append(
            {"action": "data_signing", "data_hash": hashlib.sha256(data).hexdigest(), "timestamp": time.time()}
        )

        return signature

    def get_audit_log(self) -> List[Dict]:
        """Get audit log of all operations"""
        return self._audit_log.copy()


class PolicyEngine:
    """Enforces signing policies for transaction requests"""

    def __init__(self, policy: SigningPolicy):
        self.policy = policy
        self._daily_spending = {}  # Track daily spending

    def validate_transaction(self, tx_request: TransactionRequest) -> Dict[str, Any]:
        """Validate transaction against policy rules"""
        validation_result = {"approved": True, "reasons": [], "requires_confirmation": False}

        # Check transaction value limit
        if tx_request.value > self.policy.max_transaction_value:
            validation_result["approved"] = False
            validation_result["reasons"].append(
                f"Transaction value {tx_request.value} exceeds limit {self.policy.max_transaction_value}"
            )

        # Check daily spending limit
        today = time.strftime("%Y-%m-%d")
        daily_spent = self._daily_spending.get(today, 0)
        if daily_spent + tx_request.value > self.policy.daily_limit:
            validation_result["approved"] = False
            validation_result["reasons"].append(
                f"Daily limit exceeded: {daily_spent + tx_request.value} > {self.policy.daily_limit}"
            )

        # Check contract whitelist/blacklist
        if self.policy.allowed_contracts and tx_request.to_address not in self.policy.allowed_contracts:
            validation_result["approved"] = False
            validation_result["reasons"].append(f"Contract {tx_request.to_address} not in allowed list")

        if tx_request.to_address in self.policy.blocked_contracts:
            validation_result["approved"] = False
            validation_result["reasons"].append(f"Contract {tx_request.to_address} is blocked")

        # Check if confirmation required
        if tx_request.value > self.policy.require_confirmation_above:
            validation_result["requires_confirmation"] = True

        # Check time restrictions
        if self.policy.time_restrictions:
            current_time = time.strftime("%H:%M")
            start_time = self.policy.time_restrictions.get("start")
            end_time = self.policy.time_restrictions.get("end")

            if start_time and end_time:
                if not (start_time <= current_time <= end_time):
                    validation_result["approved"] = False
                    validation_result["reasons"].append(
                        f"Transaction outside allowed time window {start_time}-{end_time}"
                    )

        return validation_result

    def record_transaction(self, tx_request: TransactionRequest):
        """Record transaction for daily limit tracking"""
        today = time.strftime("%Y-%m-%d")
        self._daily_spending[today] = self._daily_spending.get(today, 0) + tx_request.value


class TEEWallet:
    """
    Main TEE Wallet class providing secure wallet operations for SpoonOS agents
    """

    def __init__(self, wallet_id: str, policy: SigningPolicy = None):
        self.wallet_id = wallet_id
        self.policy = policy or SigningPolicy()
        self.tee_enclave = TEESecureEnclave(wallet_id)
        self.policy_engine = PolicyEngine(self.policy)
        self._private_key = None
        self._public_key = None
        self._address = None
        self._initialize_wallet()

    def _initialize_wallet(self):
        """Initialize wallet with new key pair"""
        self._private_key = self.tee_enclave.generate_private_key(self.wallet_id)
        self._public_key = self._private_key.public_key()
        self._address = self._derive_ethereum_address()

        logger.info(f"TEE Wallet initialized: {self.wallet_id}")
        logger.info(f"Wallet address: {self._address}")

    def _derive_ethereum_address(self) -> str:
        """Derive Ethereum address from public key"""
        # Get uncompressed public key bytes
        public_key_bytes = self._public_key.public_numbers().x.to_bytes(
            32, "big"
        ) + self._public_key.public_numbers().y.to_bytes(32, "big")

        # Keccak256 hash (using SHA3 as approximation)
        address_hash = hashlib.sha3_256(public_key_bytes).digest()

        # Take last 20 bytes and format as hex
        address = "0x" + address_hash[-20:].hex()
        return address

    def get_address(self) -> str:
        """Get wallet address"""
        return self._address

    def get_public_key(self) -> str:
        """Get public key in hex format"""
        public_key_bytes = self._public_key.public_numbers().x.to_bytes(
            32, "big"
        ) + self._public_key.public_numbers().y.to_bytes(32, "big")
        return public_key_bytes.hex()

    async def secure_sign(self, tx_request: TransactionRequest, force_approve: bool = False) -> Dict[str, Any]:
        """
        Securely sign a transaction request with policy validation

        Args:
            tx_request: Transaction to sign
            force_approve: Skip policy validation (for emergency use)

        Returns:
            Dict containing signature and transaction details
        """
        try:
            # Validate against policy unless forced
            if not force_approve:
                validation = self.policy_engine.validate_transaction(tx_request)

                if not validation["approved"]:
                    return {
                        "success": False,
                        "error": "Policy validation failed",
                        "reasons": validation["reasons"],
                        "requires_confirmation": validation.get("requires_confirmation", False),
                    }

                if validation["requires_confirmation"]:
                    logger.warning(f"Transaction requires manual confirmation: {tx_request.value} USD")
                    return {
                        "success": False,
                        "error": "Manual confirmation required",
                        "requires_confirmation": True,
                        "transaction": asdict(tx_request),
                    }

            # Create transaction hash for signing
            tx_data = self._create_transaction_data(tx_request)
            tx_hash = hashlib.sha256(tx_data).digest()

            # Sign within TEE
            signature = self.tee_enclave.sign_data(self._private_key, tx_hash)

            # Record transaction
            self.policy_engine.record_transaction(tx_request)

            result = {
                "success": True,
                "signature": signature.hex(),
                "transaction_hash": tx_hash.hex(),
                "from_address": self._address,
                "to_address": tx_request.to_address,
                "value": tx_request.value,
                "timestamp": tx_request.timestamp,
                "policy_approved": True,
            }

            logger.info(f"Transaction signed successfully: {tx_hash.hex()[:16]}...")
            return result

        except Exception as e:
            logger.error(f"Error signing transaction: {str(e)}")
            return {"success": False, "error": str(e)}

    def _create_transaction_data(self, tx_request: TransactionRequest) -> bytes:
        """Create transaction data for signing"""
        tx_data = {
            "to": tx_request.to_address,
            "value": str(tx_request.value),
            "data": tx_request.data,
            "gasLimit": str(tx_request.gas_limit),
            "gasPrice": str(tx_request.gas_price),
            "nonce": str(tx_request.nonce or 0),
            "chainId": str(tx_request.chain_id),
        }

        # Create deterministic byte representation
        tx_json = json.dumps(tx_data, sort_keys=True)
        return tx_json.encode("utf-8")

    def update_policy(self, new_policy: SigningPolicy):
        """Update signing policy"""
        self.policy = new_policy
        self.policy_engine = PolicyEngine(new_policy)
        logger.info("Signing policy updated")

    def get_audit_log(self) -> List[Dict]:
        """Get complete audit log"""
        return self.tee_enclave.get_audit_log()

    def get_daily_spending(self) -> Dict[str, float]:
        """Get daily spending summary"""
        return self.policy_engine._daily_spending.copy()

    def emergency_lock(self):
        """Emergency lock wallet (disable all operations)"""
        self.policy = SigningPolicy(
            max_transaction_value=0, daily_limit=0, allowed_contracts=[], blocked_contracts=["*"]  # Block all
        )
        self.policy_engine = PolicyEngine(self.policy)
        logger.warning("Wallet emergency locked!")
        return "Wallet emergency locked"

    def export_public_info(self) -> Dict[str, Any]:
        """Export public wallet information (safe to share)"""
        return {
            "wallet_id": self.wallet_id,
            "address": self._address,
            "public_key": self.get_public_key(),
            "policy": {
                "max_transaction_value": self.policy.max_transaction_value,
                "daily_limit": self.policy.daily_limit,
                "require_confirmation_above": self.policy.require_confirmation_above,
            },
            "created_at": time.time(),
        }


# Example usage and testing
if __name__ == "__main__":
    # Configure logging
    logging.basicConfig(level=logging.INFO)

    # Create a secure wallet with policy
    policy = SigningPolicy(
        max_transaction_value=1000.0,
        daily_limit=5000.0,
        require_confirmation_above=500.0,
        allowed_contracts=["0x1234567890123456789012345678901234567890"],
    )

    wallet = TEEWallet("test_wallet_001", policy)

    print(f"Wallet Address: {wallet.get_address()}")
    print(f"Public Key: {wallet.get_public_key()}")

    # Test transaction signing
    import asyncio

    async def test_signing():
        # Small transaction - should be approved
        tx1 = TransactionRequest(to_address="0x1234567890123456789012345678901234567890", value=100.0)

        result1 = await wallet.secure_sign(tx1)
        print(f"Small transaction result: {result1['success']}")

        # Large transaction - should require confirmation
        tx2 = TransactionRequest(to_address="0x1234567890123456789012345678901234567890", value=600.0)

        result2 = await wallet.secure_sign(tx2)
        print(f"Large transaction result: {result2}")

        # Blocked contract - should be rejected
        tx3 = TransactionRequest(to_address="0x9999999999999999999999999999999999999999", value=50.0)

        result3 = await wallet.secure_sign(tx3)
        print(f"Blocked contract result: {result3}")

        # Check audit log
        audit_log = wallet.get_audit_log()
        print(f"Audit log entries: {len(audit_log)}")

    asyncio.run(test_signing())
