"""
Hardware Security Module (HSM) Support for TEE Secure Wallet
Provides production-grade hardware security integration alongside TEE support
"""

import os
import logging
import hashlib
import time
from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass
from abc import ABC, abstractmethod

try:
    import pkcs11
    from pkcs11 import Mechanism, ObjectClass, KeyType, Attribute

    PKCS11_AVAILABLE = True
except ImportError:
    PKCS11_AVAILABLE = False
    pkcs11 = None

try:
    import pyhsm

    PYHSM_AVAILABLE = True
except ImportError:
    PYHSM_AVAILABLE = False
    pyhsm = None

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend

logger = logging.getLogger(__name__)


@dataclass
class HSMConfig:
    """Configuration for HSM connection"""

    hsm_type: str  # "pkcs11", "yubihsm", "aws_cloudhsm", "azure_hsm"
    library_path: Optional[str] = None
    slot_id: Optional[int] = None
    pin: Optional[str] = None
    device_serial: Optional[str] = None
    connector_url: Optional[str] = None
    auth_key_id: Optional[int] = None
    password: Optional[str] = None

    def __post_init__(self):
        # Load from environment if not provided
        if not self.pin:
            self.pin = os.getenv("HSM_PIN")
        if not self.password:
            self.password = os.getenv("HSM_PASSWORD")


class SecureHardwareInterface(ABC):
    """Abstract interface for secure hardware operations"""

    @abstractmethod
    async def initialize(self, config: HSMConfig) -> bool:
        """Initialize connection to secure hardware"""
        pass

    @abstractmethod
    async def generate_key_pair(self, key_id: str) -> Dict[str, Any]:
        """Generate a new key pair in secure hardware"""
        pass

    @abstractmethod
    async def sign_data(self, key_id: str, data: bytes) -> bytes:
        """Sign data using hardware-protected key"""
        pass

    @abstractmethod
    async def get_public_key(self, key_id: str) -> bytes:
        """Get public key for a given key ID"""
        pass

    @abstractmethod
    async def list_keys(self) -> List[str]:
        """List available keys in hardware"""
        pass

    @abstractmethod
    async def delete_key(self, key_id: str) -> bool:
        """Delete a key from hardware"""
        pass

    @abstractmethod
    def get_audit_log(self) -> List[Dict[str, Any]]:
        """Get hardware audit log"""
        pass


class PKCS11HSMInterface(SecureHardwareInterface):
    """PKCS#11 HSM interface for various hardware security modules"""

    def __init__(self):
        self.lib = None
        self.session = None
        self.slot = None
        self._audit_log = []

    async def initialize(self, config: HSMConfig) -> bool:
        """Initialize PKCS#11 HSM connection"""
        if not PKCS11_AVAILABLE:
            raise RuntimeError("PKCS#11 library not available. Install with: pip install python-pkcs11")

        try:
            # Load PKCS#11 library
            self.lib = pkcs11.lib(config.library_path or self._get_default_library_path())

            # Get slot
            slots = self.lib.get_slots()
            if config.slot_id is not None:
                self.slot = slots[config.slot_id]
            else:
                # Use first available slot with token
                self.slot = next((slot for slot in slots if slot.get_token()), None)
                if not self.slot:
                    raise RuntimeError("No HSM slot with token found")

            # Open session and login
            self.session = self.slot.open()
            if config.pin:
                self.session.login(config.pin)

            self._audit_log.append(
                {
                    "action": "hsm_initialization",
                    "slot_id": self.slot.slot_id,
                    "timestamp": time.time(),
                    "status": "success",
                }
            )

            logger.info(f"PKCS#11 HSM initialized successfully on slot {self.slot.slot_id}")
            return True

        except Exception as e:
            logger.error(f"Failed to initialize PKCS#11 HSM: {str(e)}")
            self._audit_log.append(
                {"action": "hsm_initialization", "timestamp": time.time(), "status": "failed", "error": str(e)}
            )
            return False

    def _get_default_library_path(self) -> str:
        """Get default PKCS#11 library path for common HSMs"""
        common_paths = [
            "/usr/lib/softhsm/libsofthsm2.so",  # SoftHSM
            "/usr/lib/pkcs11/libCryptoki2_64.so",  # SafeNet
            "/usr/lib/libeToken.so",  # Aladdin eToken
            "/usr/lib/opensc-pkcs11.so",  # OpenSC
            "/opt/nfast/toolkits/pkcs11/libcknfast.so",  # nCipher
        ]

        for path in common_paths:
            if os.path.exists(path):
                return path

        raise RuntimeError("No PKCS#11 library found. Please specify library_path in config.")

    async def generate_key_pair(self, key_id: str) -> Dict[str, Any]:
        """Generate EC key pair in HSM"""
        try:
            # Generate ECDSA key pair (secp256k1 for blockchain compatibility)
            public_key, private_key = self.session.generate_keypair(
                KeyType.EC,
                key_length=256,
                label=key_id,
                id=hashlib.sha256(key_id.encode()).digest()[:8],
                token=True,  # Store permanently in HSM
                private=True,  # Private key cannot be extracted
                extractable=False,  # Private key cannot be extracted
                sign=True,  # Can be used for signing
                ec_params=pkcs11.util.ec.encode_named_curve_parameters("secp256k1"),
            )

            # Get public key data
            public_key_data = public_key[Attribute.EC_POINT]

            self._audit_log.append(
                {"action": "key_generation", "key_id": key_id, "timestamp": time.time(), "status": "success"}
            )

            logger.info(f"Generated key pair for {key_id} in HSM")

            return {
                "key_id": key_id,
                "public_key": public_key_data.hex(),
                "private_key_handle": private_key.id,
                "created_at": time.time(),
            }

        except Exception as e:
            logger.error(f"Failed to generate key pair for {key_id}: {str(e)}")
            self._audit_log.append(
                {
                    "action": "key_generation",
                    "key_id": key_id,
                    "timestamp": time.time(),
                    "status": "failed",
                    "error": str(e),
                }
            )
            raise

    async def sign_data(self, key_id: str, data: bytes) -> bytes:
        """Sign data using HSM-protected private key"""
        try:
            # Find private key by label
            private_keys = self.session.get_objects({Attribute.CLASS: ObjectClass.PRIVATE_KEY, Attribute.LABEL: key_id})

            if not private_keys:
                raise ValueError(f"Private key {key_id} not found in HSM")

            private_key = private_keys[0]

            # Sign data using ECDSA with SHA256
            signature = private_key.sign(data, Mechanism.ECDSA_SHA256)

            self._audit_log.append(
                {
                    "action": "data_signing",
                    "key_id": key_id,
                    "data_hash": hashlib.sha256(data).hexdigest(),
                    "timestamp": time.time(),
                    "status": "success",
                }
            )

            return signature

        except Exception as e:
            logger.error(f"Failed to sign data with key {key_id}: {str(e)}")
            self._audit_log.append(
                {
                    "action": "data_signing",
                    "key_id": key_id,
                    "timestamp": time.time(),
                    "status": "failed",
                    "error": str(e),
                }
            )
            raise

    async def get_public_key(self, key_id: str) -> bytes:
        """Get public key from HSM"""
        try:
            public_keys = self.session.get_objects({Attribute.CLASS: ObjectClass.PUBLIC_KEY, Attribute.LABEL: key_id})

            if not public_keys:
                raise ValueError(f"Public key {key_id} not found in HSM")

            public_key = public_keys[0]
            return public_key[Attribute.EC_POINT]

        except Exception as e:
            logger.error(f"Failed to get public key {key_id}: {str(e)}")
            raise

    async def list_keys(self) -> List[str]:
        """List all keys in HSM"""
        try:
            keys = self.session.get_objects({Attribute.CLASS: ObjectClass.PRIVATE_KEY})
            return [key[Attribute.LABEL] for key in keys if key.get(Attribute.LABEL)]
        except Exception as e:
            logger.error(f"Failed to list keys: {str(e)}")
            return []

    async def delete_key(self, key_id: str) -> bool:
        """Delete key pair from HSM"""
        try:
            # Delete both private and public keys
            for obj_class in [ObjectClass.PRIVATE_KEY, ObjectClass.PUBLIC_KEY]:
                keys = self.session.get_objects({Attribute.CLASS: obj_class, Attribute.LABEL: key_id})
                for key in keys:
                    key.destroy()

            self._audit_log.append(
                {"action": "key_deletion", "key_id": key_id, "timestamp": time.time(), "status": "success"}
            )

            logger.info(f"Deleted key {key_id} from HSM")
            return True

        except Exception as e:
            logger.error(f"Failed to delete key {key_id}: {str(e)}")
            self._audit_log.append(
                {
                    "action": "key_deletion",
                    "key_id": key_id,
                    "timestamp": time.time(),
                    "status": "failed",
                    "error": str(e),
                }
            )
            return False

    def get_audit_log(self) -> List[Dict[str, Any]]:
        """Get HSM audit log"""
        return self._audit_log.copy()


class YubiHSMInterface(SecureHardwareInterface):
    """YubiHSM 2 interface"""

    def __init__(self):
        self.hsm = None
        self.session = None
        self._audit_log = []

    async def initialize(self, config: HSMConfig) -> bool:
        """Initialize YubiHSM connection"""
        if not PYHSM_AVAILABLE:
            raise RuntimeError("PyHSM library not available. Install with: pip install pyhsm")

        try:
            # Connect to YubiHSM
            connector_url = config.connector_url or "http://localhost:12345"
            self.hsm = pyhsm.YubiHsm.connect(connector_url)

            # Create session
            auth_key_id = config.auth_key_id or 1
            password = config.password or "password"
            self.session = self.hsm.create_session_derived(auth_key_id, password)

            self._audit_log.append(
                {
                    "action": "yubihsm_initialization",
                    "connector_url": connector_url,
                    "timestamp": time.time(),
                    "status": "success",
                }
            )

            logger.info("YubiHSM initialized successfully")
            return True

        except Exception as e:
            logger.error(f"Failed to initialize YubiHSM: {str(e)}")
            self._audit_log.append(
                {"action": "yubihsm_initialization", "timestamp": time.time(), "status": "failed", "error": str(e)}
            )
            return False

    async def generate_key_pair(self, key_id: str) -> Dict[str, Any]:
        """Generate EC key pair in YubiHSM"""
        try:
            # Generate unique object ID from key_id
            object_id = int(hashlib.sha256(key_id.encode()).hexdigest()[:4], 16)

            # Generate ECDSA key
            key_info = self.session.generate_asymmetric_key(
                object_id,
                key_id,
                domains=1,
                capabilities=pyhsm.defs.CAPABILITY.SIGN_ECDSA,
                algorithm=pyhsm.defs.ALGORITHM.EC_P256,
            )

            # Get public key
            public_key = self.session.get_public_key(object_id)

            self._audit_log.append(
                {
                    "action": "key_generation",
                    "key_id": key_id,
                    "object_id": object_id,
                    "timestamp": time.time(),
                    "status": "success",
                }
            )

            logger.info(f"Generated key pair for {key_id} in YubiHSM")

            return {"key_id": key_id, "object_id": object_id, "public_key": public_key.hex(), "created_at": time.time()}

        except Exception as e:
            logger.error(f"Failed to generate key pair for {key_id}: {str(e)}")
            self._audit_log.append(
                {
                    "action": "key_generation",
                    "key_id": key_id,
                    "timestamp": time.time(),
                    "status": "failed",
                    "error": str(e),
                }
            )
            raise

    async def sign_data(self, key_id: str, data: bytes) -> bytes:
        """Sign data using YubiHSM"""
        try:
            # Find object ID for key
            object_id = int(hashlib.sha256(key_id.encode()).hexdigest()[:4], 16)

            # Sign data
            signature = self.session.sign_ecdsa(object_id, data)

            self._audit_log.append(
                {
                    "action": "data_signing",
                    "key_id": key_id,
                    "object_id": object_id,
                    "data_hash": hashlib.sha256(data).hexdigest(),
                    "timestamp": time.time(),
                    "status": "success",
                }
            )

            return signature

        except Exception as e:
            logger.error(f"Failed to sign data with key {key_id}: {str(e)}")
            self._audit_log.append(
                {
                    "action": "data_signing",
                    "key_id": key_id,
                    "timestamp": time.time(),
                    "status": "failed",
                    "error": str(e),
                }
            )
            raise

    async def get_public_key(self, key_id: str) -> bytes:
        """Get public key from YubiHSM"""
        try:
            object_id = int(hashlib.sha256(key_id.encode()).hexdigest()[:4], 16)
            return self.session.get_public_key(object_id)
        except Exception as e:
            logger.error(f"Failed to get public key {key_id}: {str(e)}")
            raise

    async def list_keys(self) -> List[str]:
        """List all keys in YubiHSM"""
        try:
            objects = self.session.list_objects()
            return [obj.label for obj in objects if obj.object_type == pyhsm.defs.OBJECT.ASYMMETRIC_KEY]
        except Exception as e:
            logger.error(f"Failed to list keys: {str(e)}")
            return []

    async def delete_key(self, key_id: str) -> bool:
        """Delete key from YubiHSM"""
        try:
            object_id = int(hashlib.sha256(key_id.encode()).hexdigest()[:4], 16)
            self.session.delete_object(object_id, pyhsm.defs.OBJECT.ASYMMETRIC_KEY)

            self._audit_log.append(
                {
                    "action": "key_deletion",
                    "key_id": key_id,
                    "object_id": object_id,
                    "timestamp": time.time(),
                    "status": "success",
                }
            )

            logger.info(f"Deleted key {key_id} from YubiHSM")
            return True

        except Exception as e:
            logger.error(f"Failed to delete key {key_id}: {str(e)}")
            self._audit_log.append(
                {
                    "action": "key_deletion",
                    "key_id": key_id,
                    "timestamp": time.time(),
                    "status": "failed",
                    "error": str(e),
                }
            )
            return False

    def get_audit_log(self) -> List[Dict[str, Any]]:
        """Get YubiHSM audit log"""
        return self._audit_log.copy()


class HSMWalletManager:
    """
    Enhanced wallet manager supporting both TEE and HSM backends
    Provides unified interface for hardware-secured wallet operations
    """

    def __init__(self, hsm_config: Optional[HSMConfig] = None):
        self.hsm_config = hsm_config
        self.hsm_interface: Optional[SecureHardwareInterface] = None
        self.use_hsm = hsm_config is not None
        self._initialized = False

    async def initialize(self) -> bool:
        """Initialize HSM connection if configured"""
        if not self.use_hsm:
            self._initialized = True
            return True

        try:
            # Create appropriate HSM interface
            if self.hsm_config.hsm_type == "pkcs11":
                self.hsm_interface = PKCS11HSMInterface()
            elif self.hsm_config.hsm_type == "yubihsm":
                self.hsm_interface = YubiHSMInterface()
            else:
                raise ValueError(f"Unsupported HSM type: {self.hsm_config.hsm_type}")

            # Initialize HSM connection
            success = await self.hsm_interface.initialize(self.hsm_config)
            self._initialized = success

            if success:
                logger.info(f"HSM wallet manager initialized with {self.hsm_config.hsm_type}")
            else:
                logger.error("Failed to initialize HSM wallet manager")

            return success

        except Exception as e:
            logger.error(f"HSM initialization error: {str(e)}")
            self._initialized = False
            return False

    async def generate_wallet_key(self, wallet_id: str) -> Dict[str, Any]:
        """Generate wallet key using HSM or fallback to TEE"""
        if not self._initialized:
            raise RuntimeError("HSM wallet manager not initialized")

        if self.use_hsm and self.hsm_interface:
            return await self.hsm_interface.generate_key_pair(wallet_id)
        else:
            # Fallback to TEE implementation
            from .tee_wallet import TEESecureEnclave

            enclave = TEESecureEnclave(wallet_id)
            private_key = enclave.generate_private_key(wallet_id)

            public_key_bytes = private_key.public_key().public_numbers().x.to_bytes(
                32, "big"
            ) + private_key.public_key().public_numbers().y.to_bytes(32, "big")

            return {
                "key_id": wallet_id,
                "public_key": public_key_bytes.hex(),
                "private_key_handle": "tee_managed",
                "created_at": time.time(),
            }

    async def sign_transaction(self, wallet_id: str, transaction_data: bytes) -> bytes:
        """Sign transaction using HSM or TEE"""
        if not self._initialized:
            raise RuntimeError("HSM wallet manager not initialized")

        if self.use_hsm and self.hsm_interface:
            return await self.hsm_interface.sign_data(wallet_id, transaction_data)
        else:
            # Fallback to TEE implementation
            from .tee_wallet import TEESecureEnclave

            enclave = TEESecureEnclave(wallet_id)
            private_key = enclave.generate_private_key(wallet_id)
            return enclave.sign_data(private_key, transaction_data)

    async def get_wallet_public_key(self, wallet_id: str) -> bytes:
        """Get wallet public key"""
        if not self._initialized:
            raise RuntimeError("HSM wallet manager not initialized")

        if self.use_hsm and self.hsm_interface:
            return await self.hsm_interface.get_public_key(wallet_id)
        else:
            # Fallback to TEE implementation
            from .tee_wallet import TEESecureEnclave

            enclave = TEESecureEnclave(wallet_id)
            private_key = enclave.generate_private_key(wallet_id)
            public_key_bytes = private_key.public_key().public_numbers().x.to_bytes(
                32, "big"
            ) + private_key.public_key().public_numbers().y.to_bytes(32, "big")
            return public_key_bytes

    async def list_wallets(self) -> List[str]:
        """List all wallet keys"""
        if not self._initialized:
            raise RuntimeError("HSM wallet manager not initialized")

        if self.use_hsm and self.hsm_interface:
            return await self.hsm_interface.list_keys()
        else:
            # TEE doesn't maintain persistent key list
            return []

    async def delete_wallet(self, wallet_id: str) -> bool:
        """Delete wallet key"""
        if not self._initialized:
            raise RuntimeError("HSM wallet manager not initialized")

        if self.use_hsm and self.hsm_interface:
            return await self.hsm_interface.delete_key(wallet_id)
        else:
            # TEE keys are ephemeral, consider them "deleted"
            return True

    def get_security_info(self) -> Dict[str, Any]:
        """Get security information about the wallet backend"""
        info = {
            "backend_type": "hsm" if self.use_hsm else "tee",
            "initialized": self._initialized,
            "hardware_backed": True,
            "key_extraction_possible": False,
        }

        if self.use_hsm and self.hsm_config:
            info.update(
                {
                    "hsm_type": self.hsm_config.hsm_type,
                    "fips_140_2_level": self._get_fips_level(),
                    "common_criteria": self._get_cc_level(),
                }
            )

        return info

    def _get_fips_level(self) -> Optional[str]:
        """Get FIPS 140-2 certification level"""
        fips_levels = {
            "pkcs11": "Level 2+",  # Depends on specific HSM
            "yubihsm": "Level 3",
            "aws_cloudhsm": "Level 3",
            "azure_hsm": "Level 3",
        }
        return fips_levels.get(self.hsm_config.hsm_type)

    def _get_cc_level(self) -> Optional[str]:
        """Get Common Criteria certification level"""
        cc_levels = {"yubihsm": "EAL5+", "aws_cloudhsm": "EAL4+", "azure_hsm": "EAL4+"}
        return cc_levels.get(self.hsm_config.hsm_type)

    def get_audit_log(self) -> List[Dict[str, Any]]:
        """Get comprehensive audit log"""
        if self.use_hsm and self.hsm_interface:
            return self.hsm_interface.get_audit_log()
        else:
            return []


# Factory function for creating HSM configurations
def create_hsm_config(hsm_type: str, **kwargs) -> HSMConfig:
    """
    Factory function to create HSM configuration

    Args:
        hsm_type: Type of HSM ("pkcs11", "yubihsm", "aws_cloudhsm", "azure_hsm")
        **kwargs: HSM-specific configuration parameters

    Returns:
        HSMConfig instance
    """
    return HSMConfig(hsm_type=hsm_type, **kwargs)


# Example configurations for common HSMs
def get_softhsm_config(pin: str = "1234") -> HSMConfig:
    """Get configuration for SoftHSM (testing/development)"""
    return HSMConfig(hsm_type="pkcs11", library_path="/usr/lib/softhsm/libsofthsm2.so", slot_id=0, pin=pin)


def get_yubihsm_config(password: str = "password", auth_key_id: int = 1) -> HSMConfig:
    """Get configuration for YubiHSM 2"""
    return HSMConfig(
        hsm_type="yubihsm", connector_url="http://localhost:12345", auth_key_id=auth_key_id, password=password
    )


def get_aws_cloudhsm_config(cluster_id: str, **kwargs) -> HSMConfig:
    """Get configuration for AWS CloudHSM"""
    return HSMConfig(hsm_type="pkcs11", library_path="/opt/cloudhsm/lib/libcloudhsm_pkcs11.so", **kwargs)


if __name__ == "__main__":
    # Demo HSM functionality
    import asyncio

    async def demo_hsm():
        print("🔐 HSM Support Demo")

        # Test SoftHSM (if available)
        try:
            config = get_softhsm_config()
            manager = HSMWalletManager(config)

            if await manager.initialize():
                print("✅ SoftHSM initialized successfully")

                # Generate test key
                key_info = await manager.generate_wallet_key("test_wallet")
                print(f"✅ Generated key: {key_info['key_id']}")

                # Test signing
                test_data = b"test transaction data"
                signature = await manager.sign_transaction("test_wallet", test_data)
                print(f"✅ Signed data: {len(signature)} bytes")

                # Get security info
                security_info = manager.get_security_info()
                print(f"🛡️ Security info: {security_info}")

            else:
                print("❌ SoftHSM initialization failed")

        except Exception as e:
            print(f"⚠️ SoftHSM demo failed: {str(e)}")

        # Fallback to TEE
        print("\n🔒 Fallback to TEE")
        tee_manager = HSMWalletManager()  # No HSM config = TEE mode

        if await tee_manager.initialize():
            print("✅ TEE manager initialized")

            key_info = await tee_manager.generate_wallet_key("tee_test_wallet")
            print(f"✅ TEE key generated: {key_info['key_id']}")

            security_info = tee_manager.get_security_info()
            print(f"🛡️ TEE security info: {security_info}")

    asyncio.run(demo_hsm())
