import json
import os
import sys # To exit script if needed
from web3 import Web3
from dotenv import load_dotenv

load_dotenv()

# --- Configuration ---
COMPILED_CONTRACT_FILE = "compiled_contract.json"
NODE_URI = os.getenv("BLOCKCHAIN_NODE_URI")
DEPLOYER_KEY = os.getenv("DEPLOYER_PRIVATE_KEY") # Private key for deployment account
ENV_FILE = ".env" # To remind user which file to update
# --- End Configuration ---


def deploy_contract():
    """Deploys the contract using ABI/Bytecode from the compiled file."""
    print("Attempting to deploy contract...")

    # --- Basic Input Validation ---
    if not NODE_URI:
        print("Error: BLOCKCHAIN_NODE_URI not set in .env")
        return None
    if not DEPLOYER_KEY or not DEPLOYER_KEY.startswith("0x"): # Added 0x check
        print("Error: DEPLOYER_PRIVATE_KEY not set correctly (must start with 0x) in .env")
        return None
    if not os.path.exists(COMPILED_CONTRACT_FILE):
        print(f"Error: Compiled file not found at {COMPILED_CONTRACT_FILE}. Run compile_contract.py first.")
        return None
    # --- End Validation ---

    # --- Load Compiled Contract Data ---
    try:
        with open(COMPILED_CONTRACT_FILE, 'r') as f:
            compiled_data = json.load(f)
        abi = compiled_data.get('abi')
        bytecode = compiled_data.get('bytecode')
        contract_name = compiled_data.get('contractName', 'Unknown')
        if not abi or not bytecode:
            print("Error: ABI or Bytecode missing in compiled file.")
            return None
        print(f"Loaded ABI and Bytecode for '{contract_name}'")
    except Exception as e:
        print(f"Error loading compiled contract file '{COMPILED_CONTRACT_FILE}': {e}")
        return None
    # --- End Load Data ---

    # --- Connect to Blockchain ---
    try:
        w3 = Web3(Web3.HTTPProvider(NODE_URI))
        if not w3.is_connected():
            print(f"Failed to connect to blockchain node at {NODE_URI}")
            return None
        print(f"Connected to blockchain: {NODE_URI}, Chain ID: {w3.eth.chain_id}")

        # Get deployer account from private key
        try:
             deployer_account = w3.eth.account.from_key(DEPLOYER_KEY)
        except ValueError as e:
             print(f"Error: Invalid DEPLOYER_PRIVATE_KEY format: {e}")
             print("Ensure the key starts with 0x and contains 64 hexadecimal characters.")
             return None

        deployer_address = deployer_account.address
        print(f"Using deployer account: {deployer_address}")

        # Check balance
        balance = w3.eth.get_balance(deployer_address)
        print(f"Deployer balance: {w3.from_wei(balance, 'ether')} ETH")
        if balance == 0:
            print("Error: Deployer account has zero balance. Deployment cannot proceed.")
            return None # Exit if no balance

    except Exception as e:
        print(f"Error connecting to blockchain or setting up account: {e}")
        import traceback
        traceback.print_exc()
        return None
    # --- End Connect ---


    # --- Deploy Contract ---
    try:
        print("Deploying contract...")
        # Create contract factory instance
        ContractFactory = w3.eth.contract(abi=abi, bytecode=bytecode)

        # Estimate gas
        deployment_gas_limit = 3000000 # Default gas limit if estimation fails
        try:
             # Estimate gas for the constructor deployment
             gas_estimate = ContractFactory.constructor().estimate_gas({'from': deployer_address})
             print(f"Estimated deployment gas: {gas_estimate}")
             deployment_gas_limit = int(gas_estimate * 1.2) # Add buffer
        except Exception as e:
             # Check if the error is specifically 'invalid opcode' or similar revert
             if 'invalid opcode' in str(e) or 'execution reverted' in str(e):
                  print(f"Fatal Error during Gas Estimation: {e}")
                  print("This often indicates an EVM incompatibility (check Ganache/Hardhat hard fork vs Solc version) or an error in the contract constructor.")
                  return None # Stop deployment if estimation fails due to revert
             else:
                  print(f"Warning: Could not estimate deployment gas: {e}. Using default limit: {deployment_gas_limit}")


        # Build transaction for constructor
        tx_params = {
            'from': deployer_address,
            'nonce': w3.eth.get_transaction_count(deployer_address),
            'gasPrice': w3.eth.gas_price, # Use current gas price
            'gas': deployment_gas_limit,
        }
        unsigned_tx = ContractFactory.constructor().build_transaction(tx_params)

        # Sign transaction
        signed_tx = w3.eth.account.sign_transaction(unsigned_tx, private_key=DEPLOYER_KEY)

        # Send transaction
        tx_hash = w3.eth.send_raw_transaction(signed_tx.rawTransaction)
        print(f"Deployment transaction sent! Hash: {w3.to_hex(tx_hash)}")

        # Wait for transaction receipt
        print("Waiting for transaction receipt...")
        tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=240) # Increased timeout

        contract_address = tx_receipt.get('contractAddress') # Use .get for safety

        if not contract_address:
             print("Error: Deployment transaction succeeded but no contract address found in receipt!")
             print(tx_receipt)
             return None

        print("-" * 60)
        print(f"Contract Deployed Successfully!")
        print(f"Contract Address: {contract_address}")
        print(f"Block Number: {tx_receipt.get('blockNumber')}")
        print(f"Gas Used: {tx_receipt.get('gasUsed')}")
        print("-" * 60)
        print(f"IMPORTANT: Update your {ENV_FILE} file with:")
        print(f"CONTRACT_ADDRESS={contract_address}")
        print("-" * 60)
        return contract_address

    except ValueError as e:
         # Catch specific revert errors if possible from the ValueError content
         error_data = e.args[0] if e.args else {}
         if isinstance(error_data, dict) and 'message' in error_data:
             print(f"Deployment Failed! Blockchain Error: {error_data['message']}")
             if 'stack' in error_data: # Often includes Ganache/Hardhat internal stack
                 print("--- Node Stack Trace (if available) ---")
                 print(error_data['stack'])
                 print("---------------------------------------")
         else:
             print(f"Deployment Failed! ValueError: {e}")
         import traceback
         traceback.print_exc() # Print Python traceback too
         return None
    except Exception as e:
        print(f"An unexpected error occurred during deployment: {e}")
        import traceback
        traceback.print_exc()
        return None

if __name__ == "__main__":
    deployed_address = deploy_contract()
    if not deployed_address:
        print("Deployment failed.")
        sys.exit(1) # Exit with error code if deployment fails
    else:
        print("Deployment script finished.")