#!/usr/bin/env python3
"""Basic functionality test for GitHub Actions"""

import sys
import asyncio
import os

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../src'))

async def basic_test():
    from tee_wallet import TEEWallet, TransactionRequest
    
    wallet = TEEWallet('github_test')
    tx = TransactionRequest('0x742d35Cc6634C0532925a3b844Bc9e7595f1234', 100.0)
    result = await wallet.secure_sign(tx)
    
    if result['success']:
        print('✓ Basic functionality test passed')
        return True
    else:
        print(f'✗ Basic functionality test failed: {result.get("error")}')
        return False

if __name__ == "__main__":
    success = asyncio.run(basic_test())
    sys.exit(0 if success else 1)