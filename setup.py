"""
Setup script for TEE Secure Wallet Integration
Production-ready package configuration for SpoonOS Developer Call
"""

from setuptools import setup, find_packages
import os

# Read README for long description
def read_readme():
    with open("README.md", "r", encoding="utf-8") as fh:
        return fh.read()

# Read requirements
def read_requirements():
    with open("requirements.txt", "r", encoding="utf-8") as fh:
        return [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="spoon-tee-wallet",
    version="1.0.0",
    author="SpoonOS Developer",
    author_email="developer@spoonos.ai",
    description="TEE Secure Wallet Integration for SpoonOS - Hardware-secured private key management for AI agents",
    long_description=read_readme(),
    long_description_content_type="text/markdown",
    url="https://github.com/XSpoonAi/spoon-tee-wallet",
    project_urls={
        "Bug Tracker": "https://github.com/XSpoonAi/spoon-tee-wallet/issues",
        "Documentation": "https://github.com/XSpoonAi/spoon-tee-wallet/docs",
        "Source Code": "https://github.com/XSpoonAi/spoon-tee-wallet",
    },
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Topic :: Security :: Cryptography",
        "Topic :: Office/Business :: Financial",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Operating System :: OS Independent",
    ],
    package_dir={"": "src"},
    packages=find_packages(where="src"),
    python_requires=">=3.8",
    install_requires=read_requirements(),
    extras_require={
        "dev": [
            "pytest>=7.4.0",
            "pytest-asyncio>=0.21.0",
            "pytest-cov>=4.1.0",
            "black>=23.0.0",
            "flake8>=6.0.0",
            "mypy>=1.7.0",
        ],
        "hardware": [
            "pyhsm>=1.2.0",
            "pkcs11>=0.7.0",
        ],
        "sgx": [
            "sgx-sdk>=2.0.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "tee-wallet-demo=demo_usage:main",
        ],
    },
    include_package_data=True,
    zip_safe=False,
    keywords="tee, wallet, security, blockchain, spoonos, ai, agent, cryptography",
)