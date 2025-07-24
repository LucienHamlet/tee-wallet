#!/usr/bin/env python3
"""Release test suite for GitHub Actions"""

import sys
import asyncio
import os

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../src'))

async def release_test_suite():
    try:
        from tee_wallet import TEEWallet, SigningPolicy, TransactionRequest
        from spoon_integration import create_secure_agent, SpoonOSIntegration
        
        print('=== Release Test Suite ===')
        
        # Test 1: Core functionality
        print('1. Testing core wallet functionality...')
        wallet = TEEWallet('release_test')
        tx = TransactionRequest('0x742d35Cc6634C0532925a3b844Bc9e7595f1234', 100.0)
        result = await wallet.secure_sign(tx)
        if not result['success']:
            print(f'   ✗ Core functionality test failed: {result.get("error")}')
            return False
        print('   ✅ Core functionality passed')
        
        # Test 2: Policy enforcement
        print('2. Testing policy enforcement...')
        policy = SigningPolicy(max_transaction_value=50.0)
        policy_wallet = TEEWallet('policy_test', policy)
        
        large_tx = TransactionRequest('0x742d35Cc6634C0532925a3b844Bc9e7595f1234', 100.0)
        result = await policy_wallet.secure_sign(large_tx)
        if result['success']:
            print('   ✗ Policy enforcement test failed - large transaction should be blocked')
            return False
        print('   ✅ Policy enforcement passed')
        
        # Test 3: SpoonOS integration
        print('3. Testing SpoonOS integration...')
        integration = SpoonOSIntegration()
        parse_result = integration._parse_with_regex('Send 1 ETH to 0x742d35Cc6634C0532925a3b844Bc9e7595f1234')
        if not parse_result['success']:
            print(f'   ✗ Integration test failed: {parse_result}')
            return False
        print('   ✅ SpoonOS integration passed')
        
        # Test 4: Agent creation
        print('4. Testing agent creation...')
        agent = create_secure_agent('release_agent')
        if not agent.wallet.get_address().startswith('0x'):
            print('   ✗ Agent creation test failed - invalid address')
            return False
        print('   ✅ Agent creation passed')
        
        print('=== All Release Tests Passed! ===')
        return True
        
    except Exception as e:
        print(f'✗ Release test suite failed: {e}')
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = asyncio.run(release_test_suite())
    sys.exit(0 if success else 1)