"""
Comprehensive tests for TEE Secure Wallet
Tests all core functionality including security policies and SpoonOS integration
"""

import pytest
import asyncio
import time
from unittest.mock import Mock, patch

import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'src'))

from tee_wallet import TEEWallet, SigningPolicy, TransactionRequest, TEESecureEnclave, PolicyEngine
from spoon_integration import SecureAgent, SecureWalletTool, create_secure_agent

class TestSigningPolicy:
    """Test signing policy validation"""
    
    def test_default_policy(self):
        """Test default policy creation"""
        policy = SigningPolicy()
        assert policy.max_transaction_value == 1000.0
        assert policy.daily_limit == 5000.0
        assert policy.allowed_contracts == []
        assert policy.blocked_contracts == []
    
    def test_custom_policy(self):
        """Test custom policy creation"""
        policy = SigningPolicy(
            max_transaction_value=500.0,
            daily_limit=2000.0,
            allowed_contracts=["0x123"],
            blocked_contracts=["0x456"]
        )
        assert policy.max_transaction_value == 500.0
        assert policy.daily_limit == 2000.0
        assert "0x123" in policy.allowed_contracts
        assert "0x456" in policy.blocked_contracts

class TestTEESecureEnclave:
    """Test TEE secure enclave functionality"""
    
    def test_enclave_creation(self):
        """Test enclave initialization"""
        enclave = TEESecureEnclave("test_enclave")
        assert enclave.enclave_id == "test_enclave"
        assert len(enclave._audit_log) == 0
    
    def test_key_generation(self):
        """Test private key generation"""
        enclave = TEESecureEnclave("test_enclave")
        key1 = enclave.generate_private_key("key1")
        key2 = enclave.generate_private_key("key2")
        
        # Keys should be different
        assert key1.private_numbers().private_value != key2.private_numbers().private_value
        
        # Should be deterministic for same key_id
        key1_again = enclave.generate_private_key("key1")
        assert key1.private_numbers().private_value == key1_again.private_numbers().private_value
        
        # Audit log should record key generation
        assert len(enclave.get_audit_log()) == 3
    
    def test_data_signing(self):
        """Test data signing within enclave"""
        enclave = TEESecureEnclave("test_enclave")
        private_key = enclave.generate_private_key("test_key")
        
        test_data = b"test transaction data"
        signature = enclave.sign_data(private_key, test_data)
        
        assert isinstance(signature, bytes)
        assert len(signature) > 0
        
        # Audit log should record signing
        audit_log = enclave.get_audit_log()
        assert len(audit_log) == 2  # key generation + signing
        assert audit_log[-1]["action"] == "data_signing"

class TestPolicyEngine:
    """Test policy enforcement engine"""
    
    def test_transaction_validation_success(self):
        """Test successful transaction validation"""
        policy = SigningPolicy(max_transaction_value=1000.0, daily_limit=5000.0)
        engine = PolicyEngine(policy)
        
        tx_request = TransactionRequest(
            to_address="0x123",
            value=500.0
        )
        
        result = engine.validate_transaction(tx_request)
        assert result["approved"] is True
        assert len(result["reasons"]) == 0
    
    def test_transaction_value_limit(self):
        """Test transaction value limit enforcement"""
        policy = SigningPolicy(max_transaction_value=1000.0)
        engine = PolicyEngine(policy)
        
        tx_request = TransactionRequest(
            to_address="0x123",
            value=1500.0  # Exceeds limit
        )
        
        result = engine.validate_transaction(tx_request)
        assert result["approved"] is False
        assert "exceeds limit" in result["reasons"][0]
    
    def test_daily_limit_enforcement(self):
        """Test daily spending limit"""
        policy = SigningPolicy(daily_limit=1000.0)
        engine = PolicyEngine(policy)
        
        # First transaction
        tx1 = TransactionRequest(to_address="0x123", value=600.0)
        result1 = engine.validate_transaction(tx1)
        assert result1["approved"] is True
        engine.record_transaction(tx1)
        
        # Second transaction that would exceed daily limit
        tx2 = TransactionRequest(to_address="0x123", value=500.0)
        result2 = engine.validate_transaction(tx2)
        assert result2["approved"] is False
        assert "Daily limit exceeded" in result2["reasons"][0]
    
    def test_contract_whitelist(self):
        """Test contract whitelist enforcement"""
        policy = SigningPolicy(allowed_contracts=["0x123", "0x456"])
        engine = PolicyEngine(policy)
        
        # Allowed contract
        tx1 = TransactionRequest(to_address="0x123", value=100.0)
        result1 = engine.validate_transaction(tx1)
        assert result1["approved"] is True
        
        # Blocked contract
        tx2 = TransactionRequest(to_address="0x789", value=100.0)
        result2 = engine.validate_transaction(tx2)
        assert result2["approved"] is False
        assert "not in allowed list" in result2["reasons"][0]
    
    def test_contract_blacklist(self):
        """Test contract blacklist enforcement"""
        policy = SigningPolicy(blocked_contracts=["0x999"])
        engine = PolicyEngine(policy)
        
        tx_request = TransactionRequest(to_address="0x999", value=100.0)
        result = engine.validate_transaction(tx_request)
        assert result["approved"] is False
        assert "is blocked" in result["reasons"][0]
    
    def test_confirmation_requirement(self):
        """Test confirmation requirement for large transactions"""
        policy = SigningPolicy(require_confirmation_above=500.0)
        engine = PolicyEngine(policy)
        
        tx_request = TransactionRequest(to_address="0x123", value=600.0)
        result = engine.validate_transaction(tx_request)
        assert result["approved"] is True
        assert result["requires_confirmation"] is True

class TestTEEWallet:
    """Test main TEE wallet functionality"""
    
    def test_wallet_initialization(self):
        """Test wallet creation and initialization"""
        wallet = TEEWallet("test_wallet")
        
        assert wallet.wallet_id == "test_wallet"
        assert wallet.get_address().startswith("0x")
        assert len(wallet.get_address()) == 42  # Ethereum address length
        assert len(wallet.get_public_key()) == 128  # Uncompressed public key hex
    
    def test_deterministic_address(self):
        """Test that same wallet_id produces same address"""
        wallet1 = TEEWallet("same_id")
        wallet2 = TEEWallet("same_id")
        
        assert wallet1.get_address() == wallet2.get_address()
        assert wallet1.get_public_key() == wallet2.get_public_key()
    
    @pytest.mark.asyncio
    async def test_successful_transaction_signing(self):
        """Test successful transaction signing"""
        policy = SigningPolicy(max_transaction_value=1000.0)
        wallet = TEEWallet("test_wallet", policy)
        
        tx_request = TransactionRequest(
            to_address="0x1234567890123456789012345678901234567890",
            value=500.0
        )
        
        result = await wallet.secure_sign(tx_request)
        
        assert result["success"] is True
        assert "signature" in result
        assert "transaction_hash" in result
        assert result["from_address"] == wallet.get_address()
        assert result["policy_approved"] is True
    
    @pytest.mark.asyncio
    async def test_policy_violation_rejection(self):
        """Test transaction rejection due to policy violation"""
        policy = SigningPolicy(max_transaction_value=1000.0)
        wallet = TEEWallet("test_wallet", policy)
        
        tx_request = TransactionRequest(
            to_address="0x1234567890123456789012345678901234567890",
            value=1500.0  # Exceeds policy limit
        )
        
        result = await wallet.secure_sign(tx_request)
        
        assert result["success"] is False
        assert "Policy validation failed" in result["error"]
        assert len(result["reasons"]) > 0
    
    @pytest.mark.asyncio
    async def test_force_approve_bypass(self):
        """Test force approval bypassing policy"""
        policy = SigningPolicy(max_transaction_value=1000.0)
        wallet = TEEWallet("test_wallet", policy)
        
        tx_request = TransactionRequest(
            to_address="0x1234567890123456789012345678901234567890",
            value=1500.0  # Exceeds policy limit
        )
        
        result = await wallet.secure_sign(tx_request, force_approve=True)
        
        assert result["success"] is True
        assert "signature" in result
    
    @pytest.mark.asyncio
    async def test_confirmation_required(self):
        """Test confirmation requirement for large transactions"""
        policy = SigningPolicy(require_confirmation_above=500.0)
        wallet = TEEWallet("test_wallet", policy)
        
        tx_request = TransactionRequest(
            to_address="0x1234567890123456789012345678901234567890",
            value=600.0
        )
        
        result = await wallet.secure_sign(tx_request)
        
        assert result["success"] is False
        assert result["requires_confirmation"] is True
        assert "Manual confirmation required" in result["error"]
    
    def test_policy_update(self):
        """Test policy update functionality"""
        wallet = TEEWallet("test_wallet")
        
        new_policy = SigningPolicy(max_transaction_value=2000.0)
        wallet.update_policy(new_policy)
        
        assert wallet.policy.max_transaction_value == 2000.0
    
    def test_emergency_lock(self):
        """Test emergency wallet lock"""
        wallet = TEEWallet("test_wallet")
        wallet.emergency_lock()
        
        assert wallet.policy.max_transaction_value == 0
        assert wallet.policy.daily_limit == 0
    
    def test_audit_log(self):
        """Test audit log functionality"""
        wallet = TEEWallet("test_wallet")
        audit_log = wallet.get_audit_log()
        
        # Should have key generation entry
        assert len(audit_log) >= 1
        assert audit_log[0]["action"] == "key_generation"
    
    def test_export_public_info(self):
        """Test public information export"""
        wallet = TEEWallet("test_wallet")
        public_info = wallet.export_public_info()
        
        assert public_info["wallet_id"] == "test_wallet"
        assert public_info["address"] == wallet.get_address()
        assert "public_key" in public_info
        assert "policy" in public_info
        assert "created_at" in public_info

class TestSpoonOSIntegration:
    """Test SpoonOS framework integration"""
    
    def test_secure_wallet_tool_creation(self):
        """Test SecureWalletTool creation"""
        wallet = TEEWallet("test_wallet")
        tool = SecureWalletTool(wallet)
        
        assert tool.name == "secure_wallet"
        assert "sign" in tool.description.lower()
        assert tool.wallet == wallet
    
    @pytest.mark.asyncio
    async def test_wallet_tool_get_address(self):
        """Test wallet tool address retrieval"""
        wallet = TEEWallet("test_wallet")
        tool = SecureWalletTool(wallet)
        
        result = await tool.execute("get_address")
        assert "Wallet address:" in result
        assert wallet.get_address() in result
    
    @pytest.mark.asyncio
    async def test_wallet_tool_sign_transaction(self):
        """Test wallet tool transaction signing"""
        policy = SigningPolicy(max_transaction_value=1000.0)
        wallet = TEEWallet("test_wallet", policy)
        tool = SecureWalletTool(wallet)
        
        result = await tool.execute(
            "sign_transaction",
            to_address="0x1234567890123456789012345678901234567890",
            value=500.0
        )
        
        assert "Transaction signed successfully" in result
    
    def test_secure_agent_creation(self):
        """Test SecureAgent creation"""
        agent = create_secure_agent("test_agent")
        
        assert agent.name == "secure_agent"
        assert agent.wallet is not None
        assert agent.wallet_tool is not None
    
    @pytest.mark.asyncio
    async def test_secure_agent_transfer(self):
        """Test SecureAgent transfer functionality"""
        policy_config = {"max_transaction_value": 1000.0}
        agent = create_secure_agent("test_agent", policy_config)
        
        result = await agent.secure_transfer(
            "0x1234567890123456789012345678901234567890",
            500.0
        )
        
        assert result["success"] is True
    
    @pytest.mark.asyncio
    async def test_secure_agent_batch_transfer(self):
        """Test SecureAgent batch transfer functionality"""
        agent = create_secure_agent("test_agent")
        
        transfers = [
            {"to_address": "0x1111111111111111111111111111111111111111", "amount": 100.0},
            {"to_address": "0x2222222222222222222222222222222222222222", "amount": 200.0}
        ]
        
        results = await agent.batch_transfer(transfers)
        
        assert len(results) == 2
        assert all(result["success"] for result in results)
    
    def test_wallet_status(self):
        """Test wallet status retrieval"""
        agent = create_secure_agent("test_agent")
        status = agent.get_wallet_status()
        
        assert "address" in status
        assert "policy" in status
        assert "daily_spending" in status
        assert "audit_log_entries" in status
    
    def test_emergency_lock_integration(self):
        """Test emergency lock through agent"""
        agent = create_secure_agent("test_agent")
        result = agent.emergency_lock_wallet()
        
        assert "emergency locked" in result
        assert agent.wallet.policy.max_transaction_value == 0

class TestErrorHandling:
    """Test error handling and edge cases"""
    
    @pytest.mark.asyncio
    async def test_invalid_transaction_data(self):
        """Test handling of invalid transaction data"""
        wallet = TEEWallet("test_wallet")
        
        # Invalid address format
        tx_request = TransactionRequest(
            to_address="invalid_address",
            value=100.0
        )
        
        result = await wallet.secure_sign(tx_request)
        # Should still process (address validation would be done at blockchain level)
        assert "signature" in result or "error" in result
    
    @pytest.mark.asyncio
    async def test_tool_error_handling(self):
        """Test tool error handling"""
        wallet = TEEWallet("test_wallet")
        tool = SecureWalletTool(wallet)
        
        # Test unknown action
        result = await tool.execute("unknown_action")
        assert "Unknown action" in result
        
        # Test missing required parameters
        result = await tool.execute("sign_transaction")
        assert "Error:" in result

class TestPerformance:
    """Test performance characteristics"""
    
    def test_key_generation_performance(self):
        """Test key generation performance"""
        start_time = time.time()
        
        for i in range(10):
            wallet = TEEWallet(f"perf_test_{i}")
            assert wallet.get_address() is not None
        
        end_time = time.time()
        avg_time = (end_time - start_time) / 10
        
        # Should be fast (less than 100ms per wallet)
        assert avg_time < 0.1
    
    @pytest.mark.asyncio
    async def test_signing_performance(self):
        """Test transaction signing performance"""
        wallet = TEEWallet("perf_test")
        
        start_time = time.time()
        
        for i in range(10):
            tx_request = TransactionRequest(
                to_address="0x1234567890123456789012345678901234567890",
                value=100.0
            )
            result = await wallet.secure_sign(tx_request)
            assert result["success"] is True
        
        end_time = time.time()
        avg_time = (end_time - start_time) / 10
        
        # Should be fast (less than 50ms per signature)
        assert avg_time < 0.05

if __name__ == "__main__":
    # Run tests
    pytest.main([__file__, "-v", "--tb=short"])