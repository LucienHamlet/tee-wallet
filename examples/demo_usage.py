"""
TEE Secure Wallet Demo Usage Examples
Demonstrates practical usage scenarios for the TEE wallet with SpoonOS
"""

import asyncio
import logging
import sys
import os

# Add src to path for imports
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'src'))

from tee_wallet import TEEWallet, SigningPolicy, TransactionRequest
from spoon_integration import SecureAgent, create_secure_agent, SecureWalletTool

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

async def demo_basic_wallet_operations():
    """Demonstrate basic wallet operations"""
    print("\n=== Demo 1: Basic Wallet Operations ===")
    
    # Create a wallet with custom policy
    policy = SigningPolicy(
        max_transaction_value=1000.0,
        daily_limit=5000.0,
        require_confirmation_above=500.0,
        allowed_contracts=[
            "0x1234567890123456789012345678901234567890",
            "0xA0b86a33E6417c8C2A3c6C0b8C8C8C8C8C8C8C8C"
        ]
    )
    
    wallet = TEEWallet("demo_wallet_001", policy)
    
    print(f"✅ Wallet created successfully")
    print(f"   Address: {wallet.get_address()}")
    print(f"   Public Key: {wallet.get_public_key()[:32]}...")
    
    # Test small transaction (should succeed)
    print(f"\n📤 Testing small transaction...")
    small_tx = TransactionRequest(
        to_address="0x1234567890123456789012345678901234567890",
        value=250.0
    )
    
    result = await wallet.secure_sign(small_tx)
    if result["success"]:
        print(f"   ✅ Small transaction signed successfully")
        print(f"   Transaction hash: {result['transaction_hash'][:16]}...")
    else:
        print(f"   ❌ Small transaction failed: {result['error']}")
    
    # Test large transaction (should require confirmation)
    print(f"\n📤 Testing large transaction (requires confirmation)...")
    large_tx = TransactionRequest(
        to_address="0x1234567890123456789012345678901234567890",
        value=750.0
    )
    
    result = await wallet.secure_sign(large_tx)
    if result["success"]:
        print(f"   ✅ Large transaction signed")
    else:
        print(f"   ⚠️  Large transaction requires confirmation: {result['error']}")
        print(f"   Requires confirmation: {result.get('requires_confirmation', False)}")
    
    # Test blocked contract (should fail)
    print(f"\n📤 Testing blocked contract...")
    blocked_tx = TransactionRequest(
        to_address="0x9999999999999999999999999999999999999999",  # Not in allowed list
        value=100.0
    )
    
    result = await wallet.secure_sign(blocked_tx)
    if result["success"]:
        print(f"   ❌ Blocked transaction unexpectedly succeeded")
    else:
        print(f"   ✅ Blocked transaction correctly rejected: {result['error']}")
    
    # Show audit log
    audit_log = wallet.get_audit_log()
    print(f"\n📋 Audit log contains {len(audit_log)} entries")
    for entry in audit_log[-3:]:  # Show last 3 entries
        print(f"   - {entry['action']} at {entry['timestamp']}")

async def demo_spoonos_agent_integration():
    """Demonstrate SpoonOS agent integration"""
    print("\n=== Demo 2: SpoonOS Agent Integration ===")
    
    # Create secure agent with policy
    policy_config = {
        "max_transaction_value": 800.0,
        "daily_limit": 3000.0,
        "require_confirmation_above": 400.0
    }
    
    agent = create_secure_agent("demo_agent_001", policy_config)
    
    print(f"✅ Secure agent created")
    print(f"   Agent name: {agent.name}")
    print(f"   Wallet address: {agent.wallet.get_address()}")
    
    # Test secure transfer
    print(f"\n💸 Testing secure transfer...")
    transfer_result = await agent.secure_transfer(
        to_address="0x1234567890123456789012345678901234567890",
        amount=300.0,
        token="ETH"
    )
    
    if transfer_result["success"]:
        print(f"   ✅ Transfer completed successfully")
        print(f"   Transaction hash: {transfer_result['transaction_hash'][:16]}...")
    else:
        print(f"   ❌ Transfer failed: {transfer_result['error']}")
    
    # Test batch transfers
    print(f"\n💸 Testing batch transfers...")
    transfers = [
        {"to_address": "0x1111111111111111111111111111111111111111", "amount": 150.0, "token": "ETH"},
        {"to_address": "0x2222222222222222222222222222222222222222", "amount": 200.0, "token": "USDC"},
        {"to_address": "0x3333333333333333333333333333333333333333", "amount": 100.0, "token": "DAI"}
    ]
    
    batch_results = await agent.batch_transfer(transfers)
    
    successful_transfers = sum(1 for result in batch_results if result["success"])
    print(f"   ✅ Batch transfer completed: {successful_transfers}/{len(transfers)} successful")
    
    # Show wallet status
    status = agent.get_wallet_status()
    print(f"\n📊 Wallet Status:")
    print(f"   Address: {status['address']}")
    print(f"   Daily spending: {sum(status['daily_spending'].values())} USD")
    print(f"   Audit log entries: {status['audit_log_entries']}")
    print(f"   Max transaction limit: {status['policy']['max_transaction_value']} USD")

async def demo_security_features():
    """Demonstrate security features"""
    print("\n=== Demo 3: Security Features ===")
    
    # Create wallet with strict policy
    strict_policy = SigningPolicy(
        max_transaction_value=500.0,
        daily_limit=1000.0,
        allowed_contracts=["0x1234567890123456789012345678901234567890"],
        blocked_contracts=["0x9999999999999999999999999999999999999999"],
        require_confirmation_above=200.0
    )
    
    wallet = TEEWallet("security_demo_wallet", strict_policy)
    print(f"✅ Secure wallet created with strict policy")
    
    # Test policy enforcement
    print(f"\n🛡️  Testing policy enforcement...")
    
    # Transaction exceeding limit
    over_limit_tx = TransactionRequest(
        to_address="0x1234567890123456789012345678901234567890",
        value=600.0  # Exceeds 500 limit
    )
    
    result = await wallet.secure_sign(over_limit_tx)
    print(f"   Over-limit transaction: {'❌ Blocked' if not result['success'] else '⚠️ Allowed'}")
    
    # Test daily limit
    print(f"\n💰 Testing daily limit enforcement...")
    
    # First transaction
    tx1 = TransactionRequest(to_address="0x1234567890123456789012345678901234567890", value=400.0)
    result1 = await wallet.secure_sign(tx1)
    print(f"   First transaction (400 USD): {'✅ Approved' if result1['success'] else '❌ Rejected'}")
    
    # Second transaction
    tx2 = TransactionRequest(to_address="0x1234567890123456789012345678901234567890", value=400.0)
    result2 = await wallet.secure_sign(tx2)
    print(f"   Second transaction (400 USD): {'✅ Approved' if result2['success'] else '❌ Rejected'}")
    
    # Third transaction (should exceed daily limit)
    tx3 = TransactionRequest(to_address="0x1234567890123456789012345678901234567890", value=300.0)
    result3 = await wallet.secure_sign(tx3)
    print(f"   Third transaction (300 USD): {'✅ Approved' if result3['success'] else '❌ Rejected (Daily limit)'}")
    
    # Test emergency lock
    print(f"\n🚨 Testing emergency lock...")
    wallet.emergency_lock()
    
    emergency_tx = TransactionRequest(
        to_address="0x1234567890123456789012345678901234567890",
        value=10.0  # Very small amount
    )
    
    result = await wallet.secure_sign(emergency_tx)
    print(f"   Emergency locked transaction: {'❌ Blocked' if not result['success'] else '⚠️ Allowed'}")
    
    # Test force approval (emergency override)
    print(f"\n🔓 Testing force approval override...")
    force_result = await wallet.secure_sign(emergency_tx, force_approve=True)
    print(f"   Force approved transaction: {'✅ Allowed' if force_result['success'] else '❌ Still blocked'}")

async def demo_tool_integration():
    """Demonstrate tool integration with SpoonOS"""
    print("\n=== Demo 4: Tool Integration ===")
    
    # Create wallet and tool
    wallet = TEEWallet("tool_demo_wallet")
    tool = SecureWalletTool(wallet)
    
    print(f"✅ Wallet tool created")
    print(f"   Tool name: {tool.name}")
    print(f"   Tool description: {tool.description[:50]}...")
    
    # Test tool operations
    print(f"\n🔧 Testing tool operations...")
    
    # Get address
    address_result = await tool.execute("get_address")
    print(f"   Get address: {address_result}")
    
    # Get audit log
    audit_result = await tool.execute("get_audit_log")
    print(f"   Audit log: {audit_result}")
    
    # Test transaction signing via tool
    sign_result = await tool.execute(
        "sign_transaction",
        to_address="0x1234567890123456789012345678901234567890",
        value=250.0,
        gas_limit=21000
    )
    print(f"   Sign transaction: {sign_result}")
    
    # Test policy update via tool
    policy_update = {
        "max_transaction_value": 1500.0,
        "daily_limit": 7500.0,
        "require_confirmation_above": 750.0
    }
    
    policy_result = await tool.execute("update_policy", policy_update=policy_update)
    print(f"   Policy update: {policy_result}")

async def demo_advanced_scenarios():
    """Demonstrate advanced usage scenarios"""
    print("\n=== Demo 5: Advanced Scenarios ===")
    
    # Multi-wallet management
    print(f"\n👥 Multi-wallet management...")
    
    wallets = {}
    for i in range(3):
        policy = SigningPolicy(
            max_transaction_value=1000.0 * (i + 1),  # Different limits
            daily_limit=5000.0 * (i + 1)
        )
        wallets[f"wallet_{i}"] = TEEWallet(f"multi_wallet_{i}", policy)
        print(f"   Created wallet_{i}: {wallets[f'wallet_{i}'].get_address()}")
    
    # Cross-wallet operations
    print(f"\n🔄 Cross-wallet operations...")
    
    for wallet_id, wallet in wallets.items():
        tx = TransactionRequest(
            to_address="0x1234567890123456789012345678901234567890",
            value=500.0 * (int(wallet_id.split('_')[1]) + 1)
        )
        
        result = await wallet.secure_sign(tx)
        status = "✅ Success" if result["success"] else "❌ Failed"
        print(f"   {wallet_id} transaction: {status}")
    
    # Wallet analytics
    print(f"\n📈 Wallet analytics...")
    
    total_transactions = 0
    total_value = 0
    
    for wallet_id, wallet in wallets.items():
        audit_log = wallet.get_audit_log()
        daily_spending = wallet.get_daily_spending()
        
        transactions = len([entry for entry in audit_log if entry["action"] == "data_signing"])
        spending = sum(daily_spending.values())
        
        total_transactions += transactions
        total_value += spending
        
        print(f"   {wallet_id}: {transactions} transactions, {spending} USD spent")
    
    print(f"   Total: {total_transactions} transactions, {total_value} USD")

async def main():
    """Run all demos"""
    print("🚀 TEE Secure Wallet Demo Starting...")
    print("=" * 60)
    
    try:
        await demo_basic_wallet_operations()
        await demo_spoonos_agent_integration()
        await demo_security_features()
        await demo_tool_integration()
        await demo_advanced_scenarios()
        
        print("\n" + "=" * 60)
        print("✅ All demos completed successfully!")
        print("\n📝 Key Features Demonstrated:")
        print("   - TEE-secured private key management")
        print("   - Policy-based transaction validation")
        print("   - SpoonOS agent integration")
        print("   - Comprehensive audit logging")
        print("   - Emergency security controls")
        print("   - Tool-based operations")
        print("   - Multi-wallet management")
        
    except Exception as e:
        print(f"\n❌ Demo failed with error: {str(e)}")
        logger.exception("Demo execution failed")

if __name__ == "__main__":
    # Run the demo
    asyncio.run(main())