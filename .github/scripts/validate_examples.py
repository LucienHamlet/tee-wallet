#!/usr/bin/env python3
"""Examples validation script for GitHub Actions"""

import sys
import asyncio
import os

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../src'))

async def validate_examples():
    try:
        from tee_wallet import TEEWallet, SigningPolicy, TransactionRequest
        from spoon_integration import create_secure_agent, SpoonOSIntegration
        
        print('=== TEE Wallet Core Functionality Validation ===')
        
        # Test 1: Basic wallet creation
        print('1. Testing wallet creation...')
        wallet = TEEWallet('validation_wallet')
        print(f'   ✅ Wallet created: {wallet.get_address()}')
        
        # Test 2: Policy enforcement
        print('2. Testing policy enforcement...')
        policy = SigningPolicy(max_transaction_value=500.0)
        wallet_with_policy = TEEWallet('policy_wallet', policy)
        
        small_tx = TransactionRequest('0x742d35Cc6634C0532925a3b844Bc9e7595f1234', 100.0)
        result = await wallet_with_policy.secure_sign(small_tx)
        if not result['success']:
            print(f'   ✗ Small transaction failed: {result.get("error")}')
            return False
        print('   ✅ Small transaction approved')
        
        large_tx = TransactionRequest('0x742d35Cc6634C0532925a3b844Bc9e7595f1234', 1000.0)
        result = await wallet_with_policy.secure_sign(large_tx)
        if result['success']:
            print('   ✗ Large transaction should have been blocked')
            return False
        print('   ✅ Large transaction correctly blocked by policy')
        
        # Test 3: SpoonOS integration
        print('3. Testing SpoonOS integration...')
        integration = SpoonOSIntegration()
        parse_result = integration._parse_with_regex('Send 0.5 ETH to 0x742d35Cc6634C0532925a3b844Bc9e7595f1234')
        if not (parse_result['success'] and parse_result['amount'] == 0.5):
            print(f'   ✗ Transaction parsing failed: {parse_result}')
            return False
        print('   ✅ Transaction parsing works correctly')
        
        # Test 4: Secure agent creation
        print('4. Testing secure agent creation...')
        agent = create_secure_agent('test_agent', {
            'max_transaction_value': 1000.0, 
            'daily_limit': 5000.0
        })
        print(f'   ✅ Secure agent created: {agent.wallet.get_address()}')
        
        print('=== All Core Functionality Tests Passed! ===')
        return True
        
    except Exception as e:
        print(f'✗ Validation failed with error: {e}')
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = asyncio.run(validate_examples())
    sys.exit(0 if success else 1)