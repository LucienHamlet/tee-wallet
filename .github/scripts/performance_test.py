#!/usr/bin/env python3
"""Performance test script for GitHub Actions"""

import sys
import asyncio
import time
import os

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../src'))

async def performance_test():
    try:
        from tee_wallet import TEEWallet, TransactionRequest
        
        print('Running performance test...')
        start_time = time.time()
        
        # Create multiple wallets
        wallets = []
        for i in range(10):
            wallet = TEEWallet(f'perf_test_{i}')
            wallets.append(wallet)
        
        # Process multiple transactions
        tasks = []
        for i, wallet in enumerate(wallets):
            tx = TransactionRequest(
                to_address=f'0x742d35Cc6634C0532925a3b844Bc9e759{i:04d}',
                value=50.0 + i
            )
            tasks.append(wallet.secure_sign(tx))
        
        results = await asyncio.gather(*tasks)
        end_time = time.time()
        
        successful = sum(1 for r in results if r['success'])
        print(f'✅ Processed {len(results)} transactions in {end_time - start_time:.2f}s')
        print(f'✅ Success rate: {successful}/{len(results)}')
        
        return successful == len(results)
        
    except Exception as e:
        print(f'✗ Performance test failed: {e}')
        return False

if __name__ == "__main__":
    success = asyncio.run(performance_test())
    sys.exit(0 if success else 1)