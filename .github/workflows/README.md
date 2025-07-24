# GitHub Actions Workflows

This directory contains comprehensive CI/CD workflows to ensure project quality and correctness.

## Workflows Overview

### 🔧 Build and Test (`build-and-test.yml`)
- **Triggers**: Push/PR to main branches
- **Python Versions**: 3.9, 3.10, 3.11, 3.12
- **Features**:
  - Code linting with flake8
  - Import validation
  - Basic functionality testing
  - Code structure validation
  - Security scanning with Bandit
  - Dependency vulnerability checks

### 🧪 Examples Validation (`examples-validation.yml`)
- **Triggers**: Push/PR + daily schedule
- **Purpose**: Validate core functionality and examples
- **Features**:
  - Core wallet functionality testing
  - Policy enforcement validation
  - SpoonOS integration testing
  - Performance benchmarking
  - Memory usage validation
  - Cross-platform compatibility

### 🔄 Submodule Sync (`submodule-sync.yml`)
- **Triggers**: Push/PR + weekly schedule + manual dispatch
- **Purpose**: Manage SpoonOS submodule integration
- **Features**:
  - Submodule integrity validation
  - Update detection and testing
  - Cross-version compatibility matrix
  - Integration path validation

### 🚀 Release (`release.yml`)
- **Triggers**: Version tags + manual dispatch
- **Purpose**: Automated release and deployment
- **Features**:
  - Full test suite execution
  - Package building and validation
  - Security validation
  - GitHub release creation
  - Artifact publishing

## Workflow Status

The workflows provide comprehensive validation of:

- ✅ **Code Quality**: Linting and style checks
- ✅ **Functionality**: Core wallet operations
- ✅ **Security**: Vulnerability scanning
- ✅ **Integration**: SpoonOS submodule compatibility
- ✅ **Performance**: Load testing and benchmarks
- ✅ **Compatibility**: Multi-Python version support

## Local Testing

You can test workflow components locally:

```bash
# Test basic imports
python -c "import sys; sys.path.insert(0, 'src'); import tee_wallet, spoon_integration"

# Test core functionality
python -c "
import sys, asyncio
sys.path.insert(0, 'src')
from tee_wallet import TEEWallet, TransactionRequest

async def test():
    wallet = TEEWallet('test')
    tx = TransactionRequest('0x742d35Cc6634C0532925a3b844Bc9e7595f1234', 100.0)
    result = await wallet.secure_sign(tx)
    print('✅ Test passed' if result['success'] else '❌ Test failed')

asyncio.run(test())
"

# Run security scan (requires bandit)
pip install bandit && bandit -r src/
```

## Badge Status

Add these badges to your README.md:

```markdown
![Build Status](https://github.com/LucienHamlet/tee-wallet/workflows/Build%20and%20Test/badge.svg)
![Examples](https://github.com/LucienHamlet/tee-wallet/workflows/Examples%20Validation/badge.svg)
![Submodules](https://github.com/LucienHamlet/tee-wallet/workflows/Submodule%20Sync%20and%20Validation/badge.svg)
```

## Contributing

When contributing:

1. Ensure all workflows pass locally
2. Add tests for new functionality
3. Update documentation as needed
4. Follow security best practices

The workflows will automatically validate your changes and provide feedback through PR checks.