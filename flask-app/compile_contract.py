import solcx
import json
import os
from dotenv import load_dotenv

load_dotenv()

# --- Configuration ---
CONTRACTS_DIR = "contracts"
SOURCE_FILE = os.path.join(CONTRACTS_DIR, "MedicalRecords.sol")
COMPILED_OUTPUT_FILE = "compiled_contract.json"
CONTRACT_NAME = "MedicalRecords" # The specific contract we want from the file
# --- End Configuration ---

def compile_contracts():
    """Compiles the Solidity contract using solcx and saves ABI/Bytecode."""
    print("Attempting to compile contracts...")

    # --- Install/Set Solidity Compiler Version ---
    try:
        installed_versions = solcx.get_installed_solc_versions()
        print(f"Installed Solc versions: {installed_versions}")

        target_version = os.getenv("SOLC_VERSION") # Optional: Get from .env
        if target_version:
             print(f"Target Solc version from .env: {target_version}")
             # Check if target_version is string representation of Version object
             target_version_str = str(target_version)
             is_installed = any(str(v) == target_version_str for v in installed_versions)

             if not is_installed:
                 print(f"Installing solc version {target_version_str}...")
                 solcx.install_solc(target_version_str)
             solcx.set_solc_version(target_version_str, silent=True)

        elif installed_versions:
             # Use the latest installed version if none specified
             latest_version = str(installed_versions[-1])
             print(f"Using latest installed solc version: {latest_version}")
             solcx.set_solc_version(latest_version, silent=True)
        else:
             print("No Solc version specified or installed. Attempting to install latest stable...")
             # Install latest stable version if none are found
             latest_stable = solcx.get_available_solc_versions()[0] # Typically latest stable is first
             print(f"Installing latest stable: {latest_stable}")
             solcx.install_solc(latest_stable)
             solcx.set_solc_version(latest_stable, silent=True)

        print(f"Using Solc version: {solcx.get_solc_version()}")
    except Exception as e:
        print(f"Error setting/installing solc version: {e}")
        return False
    # --- End Compiler Version Setup ---

    print(f"Compiling {SOURCE_FILE}...")
    try:
        current_solc_version = str(solcx.get_solc_version())
        # Compile, requesting ABI and Bytecode (bin)
        compiled_sol = solcx.compile_files(
            [SOURCE_FILE],
            output_values=["abi", "bin"],
            solc_version=current_solc_version # Explicitly pass version
        )

        # Extract the specific contract's data
        # The key format is <source_file_path>:<ContractName>
        # Ensure consistent forward slashes in the key construction
        source_file_key_part = SOURCE_FILE.replace("\\", "/") # Replace backslashes with forward slashes
        contract_id = f"{source_file_key_part}:{CONTRACT_NAME}"

        if contract_id not in compiled_sol:
            print(f"Error: Contract '{CONTRACT_NAME}' not found in compilation output.")
            print(f"Available keys: {list(compiled_sol.keys())}")
            return False

        contract_interface = compiled_sol[contract_id]
        abi = contract_interface.get('abi')
        bytecode = contract_interface.get('bin')

        if not abi or not bytecode:
             print("Error: ABI or Bytecode missing in compilation output.")
             return False

        # Prepare data to save
        output_data = {
            "contractName": CONTRACT_NAME,
            "abi": abi,
            "bytecode": bytecode
        }

        # Save to JSON file
        with open(COMPILED_OUTPUT_FILE, 'w') as outfile:
            json.dump(output_data, outfile, indent=4)

        print(f"Compilation successful. ABI and Bytecode saved to {COMPILED_OUTPUT_FILE}")
        return True

    except solcx.exceptions.SolcError as e:
        print(f"Solidity Compilation Error:\n{e}")
        return False
    except Exception as e:
        print(f"An unexpected error occurred during compilation: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    if not compile_contracts():
        print("Compilation failed.")
        exit(1) # Exit if compilation fails
    else:
        print("Contract compiled successfully.")