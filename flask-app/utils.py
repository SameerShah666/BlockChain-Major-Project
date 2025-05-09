# flask-app/utils.py

import json
import os
import sys
import traceback # For detailed error logging

from web3 import Web3
from config import Config # Import Config class from config.py

# Globals for w3 and contract instance
w3 = None
contract = None

# --- Blockchain Connection ---

def connect_to_blockchain():
    """
    Connects to the blockchain node specified in Config
    and initializes the contract object using ABI and Address from Config.
    Returns True on success, False on failure.
    """
    global w3, contract
    print("Attempting to connect to blockchain...")
    try:
        if not Config.BLOCKCHAIN_NODE_URI:
             print("Error: BLOCKCHAIN_NODE_URI is not configured.")
             return False

        w3 = Web3(Web3.HTTPProvider(Config.BLOCKCHAIN_NODE_URI))

        if not w3.is_connected():
            print(f"Failed to connect to blockchain node at {Config.BLOCKCHAIN_NODE_URI}")
            w3 = None
            return False

        print(f"Connected to blockchain: {Config.BLOCKCHAIN_NODE_URI}, Chain ID: {w3.eth.chain_id}")

        # Get Address and ABI from Config
        contract_address = Config.CONTRACT_ADDRESS
        contract_abi = Config.CONTRACT_ABI

        # ABI is checked during Config loading, but address might be missing initially
        if not contract_address:
            print("Warning: CONTRACT_ADDRESS not set in config. Blockchain interactions requiring it will fail.")
            # Allow connection but contract object won't be valid
            return True # Return True as connection succeeded, but contract is unusable yet

        if not contract_abi:
             print("Error: CONTRACT_ABI not loaded.") # Should have been caught by Config
             return False

        # Create contract instance
        try:
            checksum_address = Web3.to_checksum_address(contract_address)
            contract = w3.eth.contract(address=checksum_address, abi=contract_abi) # Use loaded ABI
            print(f"Contract instance created for address: {checksum_address}")
        except ValueError as e:
             print(f"Error: Invalid CONTRACT_ADDRESS format '{contract_address}': {e}")
             return False

        return True

    except Exception as e:
        print(f"Error connecting to blockchain or creating contract instance: {e}")
        traceback.print_exc()
        w3 = None
        contract = None
        return False

# --- Transaction Sending ---

def send_transaction(function_call, user_private_key):
    """
    Signs and sends a transaction for the given function call
    using the provided user's private key.
    Returns the transaction receipt on success, None on failure.
    """
    if not w3:
        print("Error in send_transaction: Web3 not connected.")
        return None
    if not contract and hasattr(function_call, 'address'): # Check if it's a contract function call
        # This might happen if called before contract address is set in .env after deployment
        print("Error in send_transaction: Contract not initialized (address may be missing).")
        return None
    if not user_private_key or not user_private_key.startswith("0x"):
         print("Error in send_transaction: Invalid user_private_key provided.")
         return None


    try:
        # Get account object from private key
        try:
            account = w3.eth.account.from_key(user_private_key)
        except ValueError as e:
            print(f"Error: Invalid user_private_key format provided to send_transaction: {e}")
            return None

        user_address = account.address
        print(f"Sending transaction from address: {user_address}")

        # Build base transaction parameters
        current_nonce = w3.eth.get_transaction_count(user_address)
        tx_params = {
            'from': user_address,
            'nonce': current_nonce,
            'gasPrice': w3.eth.gas_price,
            # 'gas' will be estimated below
        }
        print(f"Nonce: {current_nonce}, Gas Price: {tx_params['gasPrice']}")


        # Estimate gas
        gas_limit_fallback = 500000 # Default gas limit if estimation fails
        try:
             # Estimate gas for the function call
             gas_estimate = function_call.estimate_gas({'from': user_address})
             # Add a buffer (e.g., 20%) to the estimate
             tx_params['gas'] = int(gas_estimate * 1.2)
             print(f"Estimated Gas: {gas_estimate}, Using Gas Limit: {tx_params['gas']}")
        except Exception as e:
             print(f"Warning: Could not estimate gas for function call: {e}. Using default limit: {gas_limit_fallback}")
             # Check for common revert reasons in the error message
             if 'execution reverted' in str(e):
                 print("Gas estimation failed likely due to execution revert. Check contract logic or permissions.")
                 # Optionally extract revert reason if provider supports it (requires more complex error parsing)
             tx_params['gas'] = gas_limit_fallback


        # Build the full transaction
        transaction = function_call.build_transaction(tx_params)

        # Sign the transaction
        signed_tx = w3.eth.account.sign_transaction(transaction, user_private_key)

        # Send the raw transaction
        tx_hash = w3.eth.send_raw_transaction(signed_tx.rawTransaction)
        print(f"Transaction sent! Hash: {w3.to_hex(tx_hash)}")

        # Wait for the transaction receipt
        print("Waiting for transaction confirmation...")
        tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=180) # Increased timeout

        # Check transaction status (optional but recommended)
        if tx_receipt.status == 0:
             print(f"Transaction Failed! Tx Hash: {w3.to_hex(tx_hash)}")
             print(f"Receipt: {tx_receipt}")
             return None # Indicate failure

        print(f"Transaction confirmed! Block: {tx_receipt.blockNumber}, Gas Used: {tx_receipt.gasUsed}")
        return tx_receipt

    except ValueError as ve:
        # Handle specific web3.py value errors, like insufficient funds or nonce issues
        print(f"Transaction Value Error: {ve}")
        if 'replacement transaction underpriced' in str(ve) or 'nonce too low' in str(ve):
            print(f"Nonce ({current_nonce}) or Gas Price issue likely. Check node's pending transactions or increase gas price.")
        elif 'insufficient funds' in str(ve):
            print(f"Insufficient funds in account {user_address}.")
        # Log the full error for debugging
        traceback.print_exc()
        return None
    except Exception as e:
        print(f"An unexpected error occurred sending transaction: {e}")
        traceback.print_exc()
        return None

# --- Contract Interaction Helpers (State Changing) ---

# def register_user_on_chain(user_address, name, role_enum, user_private_key):
    """Registers a user on the blockchain."""
    if not contract: return None, "Contract not loaded"
    try:
        # Security Check: Ensure the private key matches the user address
        account = w3.eth.account.from_key(user_private_key)
        if account.address != Web3.to_checksum_address(user_address):
            print("Security Error: Private key does not match the provided user address in register_user.")
            return None, "Security Error: Private key does not match user address"

        print(f"Registering user {name} ({user_address}) with role {role_enum}...")
        func_call = contract.functions.registerUser(name, role_enum)
        receipt = send_transaction(func_call, user_private_key)
        return receipt, None if receipt else "Transaction failed or reverted"
    except Exception as e:
        print(f"Error in register_user_on_chain: {e}")
        traceback.print_exc()
        return None, f"Error: {e}"

def register_user_on_chain(target_user_address, name, role_enum, registrar_private_key): # Changed params
    """Registers a target user, transaction paid by the registrar."""
    if not contract: return None, "Contract not loaded"
    if not registrar_private_key: return None, "Registrar key not provided"

    try:
        # Validate registrar key format (optional but good)
        try:
            registrar_account = w3.eth.account.from_key(registrar_private_key)
            print(f"Using registrar account: {registrar_account.address}")
        except ValueError:
             print("Invalid registrar private key format.")
             return None, "Invalid registrar key format"


        target_checksum_address = Web3.to_checksum_address(target_user_address)

        print(f"Registering user {name} ({target_checksum_address}) with role {role_enum} via registrar...")
        # Call the modified contract function
        func_call = contract.functions.registerUser(target_checksum_address, name, role_enum)

        # Send transaction using the REGISTRAR's key
        receipt = send_transaction(func_call, registrar_private_key)
        return receipt, None if receipt else "Transaction failed or reverted"
    except Exception as e:
        print(f"Error in register_user_on_chain (registrar): {e}")
        traceback.print_exc()
        return None, f"Error: {e}"

def add_record_on_chain(patient_address, data_hash, record_type, patient_private_key):
    """Adds a record hash to the blockchain for the patient."""
    if not contract: return None, "Contract not loaded"
    try:
        # Security Check: Ensure the private key matches the patient address
        account = w3.eth.account.from_key(patient_private_key)
        if account.address != Web3.to_checksum_address(patient_address):
            print("Security Error: Private key does not match patient address in add_record.")
            return None, "Security Error: Private key does not match patient address"

        print(f"Adding record for {patient_address} - Type: {record_type}, Hash: {data_hash[:10]}...")
        func_call = contract.functions.addRecord(data_hash, record_type)
        receipt = send_transaction(func_call, patient_private_key)
        return receipt, None if receipt else "Transaction failed or reverted"
    except Exception as e:
        print(f"Error in add_record_on_chain: {e}")
        traceback.print_exc()
        return None, f"Error: {e}"

def grant_access_on_chain(patient_address, doctor_address, patient_private_key):
    """Grants a doctor access to the patient's records."""
    if not contract: return None, "Contract not loaded"
    try:
        # Security Check: Ensure the private key matches the patient address
        account = w3.eth.account.from_key(patient_private_key)
        if account.address != Web3.to_checksum_address(patient_address):
            print("Security Error: Private key does not match patient address in grant_access.")
            return None, "Security Error: Private key does not match patient address"

        print(f"Granting access from patient {patient_address} to doctor {doctor_address}...")
        doctor_checksum = Web3.to_checksum_address(doctor_address)
        func_call = contract.functions.grantAccess(doctor_checksum)
        receipt = send_transaction(func_call, patient_private_key)
        return receipt, None if receipt else "Transaction failed or reverted"
    except Exception as e:
        print(f"Error in grant_access_on_chain: {e}")
        traceback.print_exc()
        return None, f"Error: {e}"

def revoke_access_on_chain(patient_address, doctor_address, patient_private_key):
    """Revokes a doctor's access to the patient's records."""
    if not contract: return None, "Contract not loaded"
    try:
        # Security Check: Ensure the private key matches the patient address
        account = w3.eth.account.from_key(patient_private_key)
        if account.address != Web3.to_checksum_address(patient_address):
            print("Security Error: Private key does not match patient address in revoke_access.")
            return None, "Security Error: Private key does not match patient address"

        print(f"Revoking access for doctor {doctor_address} from patient {patient_address}...")
        doctor_checksum = Web3.to_checksum_address(doctor_address)
        func_call = contract.functions.revokeAccess(doctor_checksum)
        receipt = send_transaction(func_call, patient_private_key)
        return receipt, None if receipt else "Transaction failed or reverted"
    except Exception as e:
        print(f"Error in revoke_access_on_chain: {e}")
        traceback.print_exc()
        return None, f"Error: {e}"

# --- Contract Interaction Helpers (View/Read-Only) ---

def get_user_info_from_chain(user_address):
    """Retrieves user information (name, role, registered status) from the blockchain."""
    if not contract:
        print("Contract not loaded in get_user_info")
        return None
    try:
        checksum_address = Web3.to_checksum_address(user_address)
        info = contract.functions.getUserInfo(checksum_address).call()
        return {"name": info[0], "role": info[1], "isRegistered": info[2]}
    except Exception as e:
        print(f"Error calling get_user_info for {user_address}: {e}")
        # Log traceback for contract call errors
        # traceback.print_exc()
        return None

def check_access_on_chain(patient_address, doctor_address):
    """Checks if a doctor has access to a patient's records (view function)."""
    if not contract:
        print("Contract not loaded in check_access")
        return False
    try:
        patient_checksum = Web3.to_checksum_address(patient_address)
        doctor_checksum = Web3.to_checksum_address(doctor_address)
        has_access = contract.functions.checkAccess(patient_checksum, doctor_checksum).call()
        return has_access
    except Exception as e:
        print(f"Error calling check_access for doctor {doctor_address} to patient {patient_address}: {e}")
        # traceback.print_exc()
        return False

def get_patient_records_list(patient_address, requesting_address):
    """
    Gets a list of record metadata for a given patient, checking permissions first.
    Returns (list_of_records, None) on success, or ([], error_message) on failure/denial.
    """
    if not contract: return [], "Contract not loaded"
    try:
        patient_checksum = Web3.to_checksum_address(patient_address)
        requesting_checksum = Web3.to_checksum_address(requesting_address)

        is_patient_self = (patient_checksum == requesting_checksum)
        has_doctor_access = False
        if not is_patient_self:
            has_doctor_access = check_access_on_chain(patient_checksum, requesting_checksum)

        if not (is_patient_self or has_doctor_access):
            print(f"Access denied for {requesting_address} to view records of {patient_address}")
            return [], "Access Denied"

        print(f"Access granted. Fetching records for patient {patient_address} requested by {requesting_address}")
        # Note: We avoid using the 'hasAccess' modifier in the contract's view functions directly
        # because .call() doesn't easily mimic msg.sender for modifiers.
        # We rely on the checkAccess view function called above.

        # Call view function that *doesn't* have restrictive modifiers
        count = contract.functions.getRecordsCount(patient_checksum).call({'from': requesting_checksum}) # Specify the 'from' address
        records = []
        print(f"Found {count} records.")
        for i in range(count):
            try:
                # Call view function that *doesn't* have restrictive modifiers
                record_data = contract.functions.getRecord(patient_checksum, i).call({'from': requesting_checksum}) # Specify the 'from' address here as well for consistency, although 'hasAccess' also protects this
                records.append({
                    "index": i,
                    "dataHash": record_data[0],
                    "timestamp": record_data[1],
                    "uploadedBy": record_data[2],
                    "recordType": record_data[3]
                })
            except Exception as call_err:
                print(f"Error calling getRecord view function for index {i}: {call_err}")
                # Optionally skip this record or add error placeholder

        print(f"Successfully fetched {len(records)} records metadata.")
        return records, None # Return list and no error

    except Exception as e:
        print(f"An unexpected error occurred in get_patient_records_list: {e}")
        traceback.print_exc()
        return [], f"Error: {e}" # Return empty list and error message

# flask-app/utils.py
# ... (keep existing imports: json, os, sys, traceback, Web3, Config, contract, w3, etc.) ...
# ... (keep existing functions: connect_to_blockchain, send_transaction, register_user_on_chain, etc.) ...

# --- Doctor Specific Utility Functions ---

def get_accessible_patients(doctor_address):
    """
    Placeholder function to retrieve patients who granted access to a doctor.

    !! IMPORTANT LIMITATION !!
    This function CANNOT be implemented correctly with the current smart contract
    and without off-chain event processing. The smart contract does not provide
    a way to query "give me all patients who granted access to Dr. X".

    A real implementation would query a separate database populated by listening
    to 'AccessGranted' and 'AccessRevoked' blockchain events, or require
    significant changes to the smart contract design (which is less scalable).

    This placeholder returns an empty list. The calling code (in app.py)
    should handle this and potentially use dummy data for UI demonstration.

    Args:
        doctor_address (str): The Ethereum address of the doctor.

    Returns:
        list: An empty list (in this placeholder implementation).
              A real implementation would return a list of patient address strings.
        str or None: An error message if checks fail, None otherwise.
    """
    print(f"--- PLACEHOLDER WARNING ---")
    print(f"Function 'get_accessible_patients' called for doctor {doctor_address}.")
    print(f"This function requires event processing or contract changes to work.")
    print(f"Returning empty list.")
    print(f"--------------------------")

    if not contract:
        return [], "Contract not loaded"
    if not Web3.is_address(doctor_address):
        return [], "Invalid doctor address format"

    # Placeholder returns empty list.
    # Real logic would query an off-chain database or call a (non-existent) contract function.
    accessible_patient_addresses = []

    return accessible_patient_addresses, None


def add_record_for_patient_by_doctor(doctor_address, doctor_private_key, patient_address, data_hash, record_type):
    """
    Adds a record hash FOR a specific patient, initiated BY a doctor.

    !! IMPORTANT PREREQUISITE !!
    This function ASSUMES the 'MedicalRecords' smart contract has been MODIFIED
    to include a function like 'addRecordForPatient(address _patient, string memory _dataHash, string memory _recordType)'
    which checks doctor role and patient access permissions internally.
    This function WILL FAIL if the corresponding contract function does not exist
    on the deployed contract instance.

    Args:
        doctor_address (str): The address of the doctor initiating the transaction.
        doctor_private_key (str): The private key of the doctor (used for signing).
        patient_address (str): The address of the patient for whom the record is being added.
        data_hash (str): The hash/CID of the record data (e.g., from IPFS/Pinata).
        record_type (str): The type of the medical record.

    Returns:
        tuple: (receipt, error_message). Receipt is the transaction receipt on success, None otherwise.
               error_message is None on success, or a string describing the error.
    """
    if not contract: return None, "Contract not loaded"
    if not Web3.is_address(patient_address): return None, "Invalid patient address format"
    if not Web3.is_address(doctor_address): return None, "Invalid doctor address format"

    try:
        # Security Check: Ensure the private key matches the doctor address
        account = w3.eth.account.from_key(doctor_private_key)
        if account.address != Web3.to_checksum_address(doctor_address):
            print("Security Error: Private key does not match the provided doctor address in add_record_for_patient.")
            return None, "Security Error: Private key does not match doctor address"

        # Prepare the call to the *new* contract function
        patient_checksum_address = Web3.to_checksum_address(patient_address)
        print(f"Doctor {doctor_address} attempting to add record for patient {patient_checksum_address}...")

        # *** ASSUMES 'addRecordForPatient' exists in the contract ***
        func_call = contract.functions.addRecordForPatient(
            patient_checksum_address,
            data_hash,
            record_type
        )

        # Send the transaction using the DOCTOR's key
        receipt = send_transaction(func_call, doctor_private_key)

        if receipt:
             print(f"Doctor successfully added record for patient. Tx: {w3.to_hex(receipt.transactionHash)}")
             return receipt, None # Success
        else:
             # Check if transaction helper indicated failure or maybe contract reverted
             print(f"Adding record for patient by doctor failed (transaction likely failed or reverted by contract).")
             # Look for revert reasons if possible (complex error parsing needed)
             return None, "Transaction failed or reverted" # Transaction helper indicated failure

    except AttributeError:
        # This likely means the contract object doesn't have the 'addRecordForPatient' function
        error_msg = "Contract Error: 'addRecordForPatient' function not found. Did you modify and redeploy the contract?"
        print(error_msg)
        traceback.print_exc()
        return None, error_msg
    except Exception as e:
        print(f"An unexpected error occurred in add_record_for_patient_by_doctor: {e}")
        traceback.print_exc()
        return None, f"Error: {e}"
    
# --- NEW: Functions to get access lists from contract ---

def get_accessible_patients_from_chain(doctor_address, doctor_private_key):
    """
    Calls the contract's getAccessiblePatients() function.
    Requires the doctor's private key to simulate 'msg.sender' for the view call.
    Returns (list_of_patient_addresses, None) on success, or ([], error_message) on failure.
    """
    if not contract: return [], "Contract not loaded"
    if not Web3.is_address(doctor_address): return [], "Invalid doctor address format"
    if not doctor_private_key: return [], "Doctor private key required for this call"

    try:
        # Security Check: Ensure key matches address
        account = w3.eth.account.from_key(doctor_private_key)
        if account.address != Web3.to_checksum_address(doctor_address):
            return [], "Security Error: Private key does not match doctor address"

        print(f"Fetching accessible patients list for doctor {doctor_address} from contract...")
        # Call the contract view function, specifying 'from' to mimic msg.sender
        patient_list = contract.functions.getAccessiblePatients().call({'from': doctor_address})
        print(f"Found {len(patient_list)} accessible patients.")
        return patient_list, None
    except Exception as e:
        # Handle potential errors like if the function doesn't exist or reverts
        error_msg = f"Error calling getAccessiblePatients for {doctor_address}: {e}"
        if "revert" in str(e) or "VM Exception" in str(e):
             error_msg += " (Possible reasons: caller not registered as doctor, contract issue)"
        elif "does not exist" in str(e):
             error_msg += " (Function 'getAccessiblePatients' may be missing from deployed contract)"
        print(error_msg)
        traceback.print_exc()
        return [], error_msg

def get_authorized_doctors_from_chain(patient_address, patient_private_key):
    """
    Calls the contract's getAuthorizedDoctors() function.
    Requires the patient's private key to simulate 'msg.sender' for the view call.
    Returns (list_of_doctor_addresses, None) on success, or ([], error_message) on failure.
    """
    if not contract: return [], "Contract not loaded"
    if not Web3.is_address(patient_address): return [], "Invalid patient address format"
    if not patient_private_key: return [], "Patient private key required for this call"

    try:
        # Security Check: Ensure key matches address
        account = w3.eth.account.from_key(patient_private_key)
        if account.address != Web3.to_checksum_address(patient_address):
            return [], "Security Error: Private key does not match patient address"

        print(f"Fetching authorized doctors list for patient {patient_address} from contract...")
        # Call the contract view function, specifying 'from' to mimic msg.sender
        doctor_list = contract.functions.getAuthorizedDoctors().call({'from': patient_address})
        print(f"Found {len(doctor_list)} authorized doctors.")
        return doctor_list, None
    except Exception as e:
        # Handle potential errors
        error_msg = f"Error calling getAuthorizedDoctors for {patient_address}: {e}"
        if "revert" in str(e) or "VM Exception" in str(e):
             error_msg += " (Possible reasons: caller not registered as patient, contract issue)"
        elif "does not exist" in str(e):
             error_msg += " (Function 'getAuthorizedDoctors' may be missing from deployed contract)"
        print(error_msg)
        traceback.print_exc()
        return [], error_msg

# ... (rest of utils.py: view functions, module load initialization) ...
# --- Initialize Connection on Module Load ---
# Perform initial connection attempt when this module is imported
if not connect_to_blockchain():
    print("WARNING: Initial blockchain connection failed during module load.")
    print("Flask app will start, but blockchain features may be unavailable until connection succeeds.")
    # Consider if sys.exit() is more appropriate depending on application needs