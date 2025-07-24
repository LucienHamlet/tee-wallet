#!/usr/bin/env python3
"""Submodule integration test for GitHub Actions"""

import sys
import os

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../src'))

def submodule_test():
    try:
        from spoon_integration import SPOON_AVAILABLE
        print(f'SpoonOS integration status: {SPOON_AVAILABLE}')
        
        spoonos_exists = os.path.exists('spoonos')
        print(f'SpoonOS path exists: {spoonos_exists}')
        
        if not spoonos_exists:
            print('✗ SpoonOS submodule directory missing')
            return False
        
        print('✅ Integration test with current submodule passed')
        return True
        
    except Exception as e:
        print(f'✗ Submodule test failed: {e}')
        return False

if __name__ == "__main__":
    success = submodule_test()
    sys.exit(0 if success else 1)