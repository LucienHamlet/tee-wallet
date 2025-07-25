"""
SpoonOS Integration for TEE Secure Wallet
Provides native integration with SpoonOS agent framework
"""

import asyncio
import logging
import os
import sys
from typing import Dict, Any, Optional, List
from dataclasses import asdict

# Add spoonos submodule to path for imports
spoon_core_path = os.path.join(os.path.dirname(__file__), "../spoonos")
if os.path.exists(spoon_core_path):
    sys.path.append(spoon_core_path)
else:
    # Try alternative path
    alt_spoon_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "../spoonos"))
    if os.path.exists(alt_spoon_path):
        sys.path.append(alt_spoon_path)

try:
    from spoon_ai.agents.base import BaseAgent
    from spoon_ai.tools.base import BaseTool
    from spoon_ai.llm.openrouter_provider import OpenRouterProvider
    from spoon_ai.utils.logger import get_logger

    SPOON_AVAILABLE = True
except ImportError as e:
    logging.warning(f"SpoonOS core modules not available: {e}")
    SPOON_AVAILABLE = False

    # Fallback implementations
    class BaseAgent:
        def __init__(self, **kwargs):
            self.name = kwargs.get("name", "agent")
            self.memory = []

        def add_message(self, role: str, content: str):
            self.memory.append({"role": role, "content": content})

    class BaseTool:
        def __init__(self):
            pass

        async def execute(self, **kwargs):
            return "Tool executed"


try:
    from .tee_wallet import TEEWallet, SigningPolicy, TransactionRequest
except ImportError:
    from tee_wallet import TEEWallet, SigningPolicy, TransactionRequest

logger = logging.getLogger(__name__)


class SecureWalletTool(BaseTool):
    """SpoonOS tool for secure wallet operations"""

    def __init__(self, wallet: TEEWallet):
        super().__init__()
        self.wallet = wallet
        self.name = "secure_wallet"
        self.description = "Securely sign blockchain transactions using TEE wallet with policy enforcement"
        self.parameters = {
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "description": "Action to perform",
                    "enum": ["sign_transaction", "get_address", "get_balance", "update_policy", "get_audit_log"],
                },
                "to_address": {"type": "string", "description": "Recipient address for transaction"},
                "value": {"type": "number", "description": "Transaction value in USD"},
                "data": {"type": "string", "description": "Transaction data (for smart contract calls)", "default": ""},
                "gas_limit": {"type": "integer", "description": "Gas limit for transaction", "default": 21000},
                "force_approve": {
                    "type": "boolean",
                    "description": "Force approval bypassing policy (emergency use only)",
                    "default": False,
                },
                "policy_update": {"type": "object", "description": "New policy settings for update_policy action"},
            },
            "required": ["action"],
        }

    async def execute(self, action: str, **kwargs) -> str:
        """Execute secure wallet operations"""
        try:
            if action == "sign_transaction":
                return await self._sign_transaction(**kwargs)
            elif action == "get_address":
                return self._get_address()
            elif action == "get_balance":
                return await self._get_balance()
            elif action == "update_policy":
                return self._update_policy(kwargs.get("policy_update", {}))
            elif action == "get_audit_log":
                return self._get_audit_log()
            else:
                return f"Unknown action: {action}"

        except Exception as e:
            logger.error(f"Error executing wallet action {action}: {str(e)}")
            return f"Error: {str(e)}"

    async def _sign_transaction(self, to_address: str, value: float, **kwargs) -> str:
        """Sign a transaction securely"""
        tx_request = TransactionRequest(
            to_address=to_address,
            value=value,
            data=kwargs.get("data", ""),
            gas_limit=kwargs.get("gas_limit", 21000),
            gas_price=kwargs.get("gas_price", 20000000000),
            chain_id=kwargs.get("chain_id", 1),
        )

        force_approve = kwargs.get("force_approve", False)
        result = await self.wallet.secure_sign(tx_request, force_approve)

        if result["success"]:
            return f"Transaction signed successfully. Hash: {result['transaction_hash'][:16]}..."
        else:
            return f"Transaction signing failed: {result.get('error', 'Unknown error')}"

    def _get_address(self) -> str:
        """Get wallet address"""
        return f"Wallet address: {self.wallet.get_address()}"

    async def _get_balance(self) -> str:
        """Get wallet balance via blockchain RPC integration"""
        try:
            address = self.wallet.get_address()

            # Implement actual blockchain balance checking
            import aiohttp
            import json

            # Example using Ethereum JSON-RPC (can be adapted for other chains)
            rpc_url = "https://eth-mainnet.alchemyapi.io/v2/demo"  # Demo endpoint

            payload = {"jsonrpc": "2.0", "method": "eth_getBalance", "params": [address, "latest"], "id": 1}

            async with aiohttp.ClientSession() as session:
                try:
                    async with session.post(rpc_url, json=payload, timeout=10) as response:
                        if response.status == 200:
                            data = await response.json()
                            if "result" in data:
                                # Convert hex balance to decimal ETH
                                balance_wei = int(data["result"], 16)
                                balance_eth = balance_wei / 10**18
                                return f"Balance: {balance_eth:.6f} ETH ({address})"
                            else:
                                return f"Balance query failed: {data.get('error', 'Unknown error')} ({address})"
                        else:
                            return f"RPC request failed with status {response.status} ({address})"
                except asyncio.TimeoutError:
                    return f"Balance query timeout ({address})"
                except Exception as e:
                    return f"Network error: {str(e)} ({address})"

        except Exception as e:
            return f"Balance check error: {str(e)}"

    def _update_policy(self, policy_data: Dict[str, Any]) -> str:
        """Update wallet signing policy"""
        try:
            new_policy = SigningPolicy(
                max_transaction_value=policy_data.get("max_transaction_value", 1000.0),
                daily_limit=policy_data.get("daily_limit", 5000.0),
                allowed_contracts=policy_data.get("allowed_contracts", []),
                blocked_contracts=policy_data.get("blocked_contracts", []),
                require_confirmation_above=policy_data.get("require_confirmation_above", 500.0),
            )

            self.wallet.update_policy(new_policy)
            return "Wallet policy updated successfully"

        except Exception as e:
            return f"Failed to update policy: {str(e)}"

    def _get_audit_log(self) -> str:
        """Get wallet audit log"""
        audit_log = self.wallet.get_audit_log()
        return (
            f"Audit log contains {len(audit_log)} entries. Recent activity: {audit_log[-3:] if audit_log else 'None'}"
        )


class SecureAgent(BaseAgent):
    """
    SpoonOS agent with integrated TEE secure wallet
    Provides secure blockchain operations for autonomous agents
    """

    def __init__(self, wallet_id: str, policy: SigningPolicy = None, **kwargs):
        super().__init__(**kwargs)

        self.name = kwargs.get("name", "secure_agent")
        self.description = "AI agent with TEE-secured wallet for safe blockchain operations"

        # Initialize TEE wallet
        self.wallet = TEEWallet(wallet_id, policy)

        # Create secure wallet tool
        self.wallet_tool = SecureWalletTool(self.wallet)

        # Initialize LLM provider if SpoonOS is available
        if SPOON_AVAILABLE:
            try:
                self.llm_provider = OpenRouterProvider(
                    api_key=os.getenv("OPENROUTER_API_KEY"), model="anthropic/sonnet-3.5"
                )
            except Exception as e:
                logger.warning(f"Could not initialize OpenRouter provider: {e}")
                self.llm_provider = None
        else:
            self.llm_provider = None

        logger.info(f"SecureAgent initialized with wallet: {self.wallet.get_address()}")

    async def step(self) -> str:
        """Execute one step of agent reasoning/action"""
        if not hasattr(self, "memory") or not self.memory:
            return "No messages to process"

        last_message = self.memory[-1]

        if last_message.get("role") == "user":
            # Process user request
            content = last_message.get("content", "").lower()

            if "sign" in content or "transfer" in content or "send" in content:
                return await self._handle_transaction_request(last_message.get("content", ""))
            elif "address" in content or "wallet" in content:
                return await self._handle_wallet_info_request()
            elif "policy" in content:
                return await self._handle_policy_request(last_message.get("content", ""))
            else:
                return "I can help with secure wallet operations. Try asking about signing transactions, wallet address, or policy management."

        return "Processed message"

    async def _handle_transaction_request(self, request: str) -> str:
        """Handle transaction signing requests with NLP parsing"""
        try:
            # Use SpoonOS LLM provider if available
            if self.llm_provider and SPOON_AVAILABLE:
                return await self._parse_with_spoon_llm(request)
            else:
                return await self._parse_with_regex(request)
        except Exception as e:
            logger.error(f"Error handling transaction request: {e}")
            return await self._parse_with_regex(request)

    async def _parse_with_spoon_llm(self, request: str) -> str:
        """Parse transaction request using SpoonOS LLM provider"""
        try:
            prompt = f"""
            Parse this transaction request and provide a response:
            "{request}"
            
            Extract: recipient address, amount, currency, and determine if this is an emergency.
            Provide a helpful response about the transaction details found.
            """

            response = await self.llm_provider.generate(prompt)
            return response
        except Exception as e:
            logger.warning(f"LLM parsing failed: {e}, using regex fallback")
            return await self._parse_with_regex(request)

    async def _parse_with_regex(self, request: str) -> str:
        """Parse transaction request using regex patterns"""
        import re

        # Enhanced NLP parsing patterns
        patterns = {
            "address": r"0x[a-fA-F0-9]{40}",
            "amount": r"(\d+(?:\.\d+)?)\s*(eth|ether|wei|gwei)?",
            "send": r"send|transfer|pay",
            "to": r"to|recipient|address",
            "emergency": r"emergency|urgent|immediate",
        }

        request_lower = request.lower()

        # Check for emergency transactions
        if re.search(patterns["emergency"], request_lower):
            return "⚠️ Emergency transaction detected. Please confirm: recipient address, amount, and urgency level."

        # Extract addresses
        addresses = re.findall(patterns["address"], request)

        # Extract amounts
        amounts = re.findall(patterns["amount"], request_lower)

        # Check if this looks like a transaction request
        if re.search(patterns["send"], request_lower) or addresses or amounts:
            response = "Transaction request detected. "

            if addresses:
                response += f"Found address: {addresses[0]}. "
            else:
                response += "Please provide recipient address (0x...). "

            if amounts:
                amount_str = f"{amounts[0][0]} {amounts[0][1] or 'ETH'}"
                response += f"Amount: {amount_str}. "
            else:
                response += "Please specify amount. "

            response += "Say 'confirm transaction' to proceed or 'cancel' to abort."
            return response

        return "To sign a transaction, please provide: recipient address (0x...), amount (e.g., 1.5 ETH), and say 'send' or 'transfer'."

    async def _handle_wallet_info_request(self) -> str:
        """Handle wallet information requests"""
        address = self.wallet.get_address()
        daily_spending = self.wallet.get_daily_spending()

        info = f"Wallet Address: {address}\n"
        info += f"Daily Spending: {sum(daily_spending.values())} USD\n"
        info += f"Policy Max Transaction: {self.wallet.policy.max_transaction_value} USD"

        return info

    async def _handle_policy_request(self, request: str) -> str:
        """Handle policy-related requests"""
        if "update" in request.lower():
            return (
                "Policy updates require specific parameters. Current policy allows transactions up to "
                + f"{self.wallet.policy.max_transaction_value} USD"
            )
        else:
            policy_info = f"Current Policy:\n"
            policy_info += f"- Max Transaction: {self.wallet.policy.max_transaction_value} USD\n"
            policy_info += f"- Daily Limit: {self.wallet.policy.daily_limit} USD\n"
            policy_info += f"- Confirmation Required Above: {self.wallet.policy.require_confirmation_above} USD\n"
            policy_info += f"- Allowed Contracts: {len(self.wallet.policy.allowed_contracts)}\n"
            policy_info += f"- Blocked Contracts: {len(self.wallet.policy.blocked_contracts)}"

            return policy_info

    async def secure_transfer(self, to_address: str, amount: float, token: str = "ETH") -> Dict[str, Any]:
        """
        Perform a secure token transfer

        Args:
            to_address: Recipient address
            amount: Amount to transfer
            token: Token type (default ETH)

        Returns:
            Transaction result
        """
        tx_request = TransactionRequest(
            to_address=to_address,
            value=await self._convert_to_usd(amount, token),  # Automatic token amount to USD conversion
        )

        result = await self.wallet.secure_sign(tx_request)

        # Add to memory for context
        self.add_message(
            "assistant",
            f"Attempted transfer of {amount} {token} to {to_address}. "
            + f"Result: {'Success' if result['success'] else 'Failed'}",
        )

        return result

    async def _convert_to_usd(self, amount: float, token: str) -> float:
        """Convert token amount to USD using real-time price data"""
        try:
            import aiohttp
            import json

            # Normalize token symbol
            token_symbol = token.upper()
            if token_symbol in ["ETH", "ETHER"]:
                token_symbol = "ethereum"
            elif token_symbol == "BTC":
                token_symbol = "bitcoin"
            elif token_symbol == "NEO":
                token_symbol = "neo"

            # Get current price from CoinGecko API
            url = f"https://api.coingecko.com/api/v3/simple/price?ids={token_symbol}&vs_currencies=usd"

            async with aiohttp.ClientSession() as session:
                try:
                    async with session.get(url, timeout=10) as response:
                        if response.status == 200:
                            data = await response.json()
                            if token_symbol in data and "usd" in data[token_symbol]:
                                price_usd = data[token_symbol]["usd"]
                                usd_value = amount * price_usd
                                logger.info(f"Converted {amount} {token} to ${usd_value:.2f} USD (rate: ${price_usd})")
                                return usd_value
                            else:
                                logger.warning(f"Price not found for {token_symbol}, using amount as-is")
                                return amount
                        else:
                            logger.warning(f"Price API request failed with status {response.status}")
                            return amount
                except asyncio.TimeoutError:
                    logger.warning("Price conversion timeout, using amount as-is")
                    return amount
                except Exception as e:
                    logger.warning(f"Price conversion error: {str(e)}, using amount as-is")
                    return amount

        except Exception as e:
            logger.error(f"Token conversion error: {str(e)}")
            return amount

    def get_wallet_status(self) -> Dict[str, Any]:
        """Get comprehensive wallet status"""
        return {
            "address": self.wallet.get_address(),
            "policy": asdict(self.wallet.policy),
            "daily_spending": self.wallet.get_daily_spending(),
            "audit_log_entries": len(self.wallet.get_audit_log()),
            "public_info": self.wallet.export_public_info(),
            "spoon_integration": SPOON_AVAILABLE,
        }

    async def batch_transfer(self, transfers: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Perform multiple transfers in batch

        Args:
            transfers: List of transfer dictionaries with to_address and amount

        Returns:
            List of transaction results
        """
        results = []
        for transfer in transfers:
            result = await self.secure_transfer(
                to_address=transfer.get("to_address"), amount=transfer.get("amount"), token=transfer.get("token", "ETH")
            )
            results.append(result)
        return results

    def emergency_lock_wallet(self) -> Dict[str, Any]:
        """
        Emergency lock the wallet

        Returns:
            Lock result
        """
        return self.wallet.emergency_lock()


class SpoonOSIntegration:
    """
    Main integration class for SpoonOS TEE Wallet
    """

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.getenv("OPENROUTER_API_KEY")

        # Initialize SpoonOS LLM provider if available
        if SPOON_AVAILABLE and self.api_key:
            try:
                self.llm_provider = OpenRouterProvider(api_key=self.api_key, model="anthropic/sonnet-3.5")
            except Exception as e:
                logger.warning(f"Could not initialize SpoonOS LLM provider: {e}")
                self.llm_provider = None
        else:
            self.llm_provider = None

    async def parse_transaction_request(self, request: str) -> Dict[str, Any]:
        """Parse natural language transaction request"""
        try:
            if self.llm_provider:
                return await self._parse_with_spoon_llm(request)
            else:
                return self._parse_with_regex(request)
        except Exception as e:
            logger.error(f"Error parsing transaction request: {e}")
            return self._parse_with_regex(request)

    async def _parse_with_spoon_llm(self, request: str) -> Dict[str, Any]:
        """Parse using SpoonOS LLM provider"""
        try:
            prompt = f"""
            Parse this transaction request and extract key information:
            "{request}"
            
            Return a JSON object with:
            - success: boolean
            - amount: number (if found)
            - currency: string (ETH, BTC, etc.)
            - recipient: string (address if found)
            - action: string (send, transfer, etc.)
            - emergency: boolean (if urgent/emergency keywords detected)
            """

            response = await self.llm_provider.generate(prompt)

            # Try to extract JSON from response
            import json
            import re

            json_match = re.search(r"\{.*\}", response, re.DOTALL)
            if json_match:
                try:
                    return json.loads(json_match.group())
                except json.JSONDecodeError:
                    pass

            # Fallback to regex if JSON parsing fails
            return self._parse_with_regex(request)

        except Exception as e:
            logger.warning(f"SpoonOS LLM parsing failed: {e}")
            return self._parse_with_regex(request)

    def _parse_with_regex(self, request: str) -> Dict[str, Any]:
        """Parse using regex patterns"""
        import re

        patterns = {
            "address": r"0x[a-fA-F0-9]{40}",
            "amount": r"(\d+(?:\.\d+)?)\s*(eth|ether|btc|bitcoin|neo|gas)?",
            "send": r"send|transfer|pay",
            "emergency": r"emergency|urgent|immediate|asap",
        }

        request_lower = request.lower()

        # Extract information
        addresses = re.findall(patterns["address"], request)
        amounts = re.findall(patterns["amount"], request_lower)
        is_send = bool(re.search(patterns["send"], request_lower))
        is_emergency = bool(re.search(patterns["emergency"], request_lower))

        result = {
            "success": bool(addresses or amounts or is_send),
            "emergency": is_emergency,
            "action": "send" if is_send else "unknown",
        }

        if addresses:
            result["recipient"] = addresses[0]

        if amounts:
            result["amount"] = float(amounts[0][0])
            result["currency"] = amounts[0][1].upper() if amounts[0][1] else "ETH"

        return result

    async def detect_emergency(self, message: str) -> Dict[str, Any]:
        """Detect emergency situations in messages"""
        try:
            if self.llm_provider:
                return await self._detect_emergency_with_spoon_llm(message)
            else:
                return self._detect_emergency_with_regex(message)
        except Exception as e:
            logger.error(f"Error detecting emergency: {e}")
            return self._detect_emergency_with_regex(message)

    async def _detect_emergency_with_spoon_llm(self, message: str) -> Dict[str, Any]:
        """Detect emergency using SpoonOS LLM"""
        try:
            prompt = f"""
            Analyze this message for emergency or security threats:
            "{message}"
            
            Return a JSON object with:
            - is_emergency: boolean
            - confidence: number (0.0 to 1.0)
            - threat_type: string (security, financial, technical, etc.)
            - severity: string (low, medium, high, critical)
            """

            response = await self.llm_provider.generate(prompt)

            # Try to extract JSON from response
            import json
            import re

            json_match = re.search(r"\{.*\}", response, re.DOTALL)
            if json_match:
                try:
                    return json.loads(json_match.group())
                except json.JSONDecodeError:
                    pass

            # Fallback to regex
            return self._detect_emergency_with_regex(message)

        except Exception as e:
            logger.warning(f"SpoonOS emergency detection failed: {e}")
            return self._detect_emergency_with_regex(message)

    def _detect_emergency_with_regex(self, message: str) -> Dict[str, Any]:
        """Detect emergency using regex patterns"""
        import re

        emergency_patterns = [
            r"urgent|emergency|immediate|asap|critical",
            r"hack|attack|breach|unauthorized|compromise",
            r"stolen|theft|fraud|scam|phishing",
            r"help|sos|alert|warning|danger",
        ]

        message_lower = message.lower()
        matches = 0
        total_patterns = len(emergency_patterns)

        for pattern in emergency_patterns:
            if re.search(pattern, message_lower):
                matches += 1

        confidence = matches / total_patterns
        is_emergency = confidence > 0.3

        # Determine threat type
        threat_type = "unknown"
        if re.search(r"hack|attack|breach|unauthorized|compromise", message_lower):
            threat_type = "security"
        elif re.search(r"stolen|theft|fraud|scam", message_lower):
            threat_type = "financial"
        elif re.search(r"urgent|emergency|critical", message_lower):
            threat_type = "operational"

        # Determine severity
        severity = "low"
        if confidence > 0.7:
            severity = "critical"
        elif confidence > 0.5:
            severity = "high"
        elif confidence > 0.3:
            severity = "medium"

        return {
            "is_emergency": is_emergency,
            "confidence": confidence,
            "threat_type": threat_type,
            "severity": severity,
        }


# Integration helper functions
def create_secure_agent(wallet_id: str, policy_config: Dict[str, Any] = None) -> SecureAgent:
    """
    Factory function to create a SecureAgent with TEE wallet

    Args:
        wallet_id: Unique identifier for the wallet
        policy_config: Policy configuration dictionary

    Returns:
        Configured SecureAgent instance
    """
    if policy_config:
        policy = SigningPolicy(
            max_transaction_value=policy_config.get("max_transaction_value", 1000.0),
            daily_limit=policy_config.get("daily_limit", 5000.0),
            allowed_contracts=policy_config.get("allowed_contracts", []),
            blocked_contracts=policy_config.get("blocked_contracts", []),
            require_confirmation_above=policy_config.get("require_confirmation_above", 500.0),
        )
    else:
        policy = SigningPolicy()

    return SecureAgent(wallet_id, policy)


def integrate_with_existing_agent(agent: BaseAgent, wallet_id: str, policy: SigningPolicy = None) -> TEEWallet:
    """
    Integrate TEE wallet with existing SpoonOS agent

    Args:
        agent: Existing SpoonOS agent
        wallet_id: Unique identifier for the wallet
        policy: Signing policy (optional)

    Returns:
        TEE wallet instance
    """
    wallet = TEEWallet(wallet_id, policy)

    # Add wallet tool to agent's available tools if it has a tool manager
    if hasattr(agent, "available_tools") and hasattr(agent.available_tools, "add_tool"):
        wallet_tool = SecureWalletTool(wallet)
        agent.available_tools.add_tool(wallet_tool)
        logger.info(f"TEE wallet integrated with agent: {agent.name}")

    return wallet


# Example usage
if __name__ == "__main__":
    import asyncio

    async def demo_secure_agent():
        # Create secure agent with custom policy
        policy_config = {"max_transaction_value": 500.0, "daily_limit": 2000.0, "require_confirmation_above": 200.0}

        agent = create_secure_agent("demo_wallet", policy_config)

        print(f"Created secure agent with wallet: {agent.wallet.get_address()}")
        print(f"SpoonOS integration available: {SPOON_AVAILABLE}")

        # Test secure transfer
        result = await agent.secure_transfer("0x1234567890123456789012345678901234567890", 100.0, "ETH")

        print(f"Transfer result: {result}")

        # Test wallet status
        status = agent.get_wallet_status()
        print(f"Wallet status: {status}")

        # Test SpoonOS integration
        integration = SpoonOSIntegration()
        parse_result = await integration.parse_transaction_request(
            "Send 0.5 ETH to 0x1234567890123456789012345678901234567890"
        )
        print(f"Parse result: {parse_result}")

        emergency_result = await integration.detect_emergency("URGENT: Unauthorized access detected!")
        print(f"Emergency detection: {emergency_result}")

    # Run demo
    asyncio.run(demo_secure_agent())
