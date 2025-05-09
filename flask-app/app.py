# flask-app/app.py
# Updated: 2025-05-01 ~11:37 PM IST

import os
import datetime # For timestamp filter
import traceback # For detailed error logging
import json # Make sure json is imported if needed

from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from werkzeug.utils import secure_filename # For handling file uploads
import requests # For Pinata/IPFS interaction
from web3 import Web3 # For address validation and other web3 functions

# --- Configuration ---
# Config object loads variables from .env
from config import Config

# --- Blockchain Utilities ---
# Import necessary functions from utils.py
# Assumes utils.py contains all required functions with previous fixes applied
from utils import (
    w3, contract, connect_to_blockchain, # w3/contract might be checked directly
    register_user_on_chain,               # Registrar pattern assumed in utils
    add_record_on_chain,                  # Patient adds own record
    grant_access_on_chain,
    revoke_access_on_chain,
    get_user_info_from_chain,
    get_patient_records_list,
    check_access_on_chain,
    add_record_for_patient_by_doctor,      # Doctor adds record for patient (requires contract change)
    get_authorized_doctors_from_chain,
    get_accessible_patients_from_chain,
)

# --- Constants ---
# UPLOAD_FOLDER might not be needed if directly streaming to Pinata/IPFS
# UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'json', 'xml', 'dcm', 'md'} # Add relevant medical/text types

# --- Flask App Initialization ---
app = Flask(__name__)
app.config.from_object(Config)
# app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER # Only needed if saving files locally first

def transfer_ether(from_address, from_private_key, to_address, amount_ether):
    """Transfers Ether from one account to another using Web3.py."""

    print("transfer_ether() was called")

    # Setup Web3 connection
    w3 = Web3(Web3.HTTPProvider(Config.BLOCKCHAIN_NODE_URI))

    if not w3.is_connected():
        print("Failed to connect to the blockchain.")
        return False

    try:
        # Ensure addresses are valid
        if not (w3.is_address(from_address) and w3.is_address(to_address)):
            raise ValueError("Invalid Ethereum address.")

        # Normalize addresses (checksum format)
        from_address = w3.to_checksum_address(from_address)
        to_address = w3.to_checksum_address(to_address)

        # Convert Ether to Wei
        amount_wei = w3.to_wei(amount_ether, 'ether')

        # Build the transaction
        txn = {
            'to': to_address,
            'value': amount_wei,
            'gas': 21000,
            'gasPrice': w3.eth.gas_price,
            'nonce': w3.eth.get_transaction_count(from_address),
            'chainId': w3.eth.chain_id
        }

        # Sign it
        signed_txn = w3.eth.account.sign_transaction(txn, private_key=from_private_key)

        # Broadcast
        txn_hash = w3.eth.send_raw_transaction(signed_txn.rawTransaction)
        txn_hex = w3.to_hex(txn_hash)

        print(f"Transaction successful. Hash: {txn_hex}")
        return txn_hex

    except Exception as e:
        print(f"Error transferring Ether: {e}")
        return False

# --- Template Filter ---
@app.template_filter('timestamp_to_datetime')
def timestamp_to_datetime_filter(s):
    """Converts a UNIX timestamp to a readable datetime string."""
    try:
        # Solidity timestamps are usually seconds since epoch
        return datetime.datetime.fromtimestamp(int(s)).strftime('%Y-%m-%d %H:%M:%S')
    except (ValueError, TypeError, OSError):
        return str(s) # Return original value if conversion fails


# --- User Session Management (INSECURE DEMO - DO NOT USE IN PRODUCTION) ---
# WARNING: Storing private keys in session is EXTREMELY INSECURE.
# This is for DEMONSTRATION PURPOSES ONLY to avoid MetaMask.
def get_current_user_key():
    """Gets the logged-in user's private key from session (INSECURE)."""
    return session.get('user_private_key')

def get_current_user_address():
    """Gets the logged-in user's address from session."""
    return session.get('user_address')

# --- Helper Functions ---
def allowed_file(filename):
    """Checks if the file extension is allowed."""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# --- Basic Routes ---

@app.route('/')
def index():
    """Homepage."""
    user_address = get_current_user_address()
    user_info = None
    connection_ok = w3 and w3.is_connected() and contract is not None

    if user_address and connection_ok:
        user_info = get_user_info_from_chain(user_address)
        if user_info is None:
             # Avoid flashing if just a transient fetch issue, maybe log instead
             print(f"Warning: Could not fetch user info for {user_address} from chain.")
    elif user_address and not connection_ok:
         flash("Blockchain connection issue, user info unavailable.", "warning")

    return render_template('index.html', user_address=user_address, user_info=user_info, connection_ok=connection_ok)

@app.route('/logout')
def logout():
    """Logs the user out by clearing the session."""
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))

# --- Registration and Login Routes ---

@app.route('/register', methods=['GET', 'POST'])
def register():
    """Handles new user registration (Patient or Doctor). Uses Registrar pattern."""
    # Check prerequisites
    if not w3 or not w3.is_connected():
        flash("Blockchain connection unavailable.", "danger")
        return render_template('register.html')
    registrar_key = Config.SERVER_ACCOUNT_PRIVATE_KEY # Using DEPLOYER_KEY loaded into this config var
    registrar_address = w3.eth.account.from_key(registrar_key).address # Get address from key
    if not registrar_key:
         flash("Server configuration error: Registrar key not set. Cannot register new users.", "danger")
         return render_template('register.html')
    if not contract:
         # Check if address is missing or connection failed after start
         if not Config.CONTRACT_ADDRESS:
              flash("Server configuration error: Contract address not set. Deploy contract first.", "danger")
         else:
              flash("Blockchain contract connection unavailable. Cannot register new users.", "danger")
         return render_template('register.html')

    if request.method == 'POST':
        name = request.form.get('name')
        role_str = request.form.get('role')

        if not name or role_str is None:
             flash("Name and Role are required.", "warning")
             return redirect(url_for('register'))

        try:
             role = int(role_str) # 0 for Patient, 1 for Doctor
             if role not in [0, 1]: raise ValueError("Invalid role value")
        except ValueError:
             flash("Invalid role selected.", "warning")
             return redirect(url_for('register'))

        # 1. Generate NEW user's key pair
        try:
            new_account = w3.eth.account.create()
            user_address = new_account.address
            user_private_key = new_account.key.hex() # Use .hex() to store safely
        except Exception as e:
             flash(f"Failed to generate blockchain account keys: {e}", 'danger')
             print(f"Key generation error: {e}")
             traceback.print_exc()
             return redirect(url_for('register'))

        # 2. Call register_user_on_chain using the registrar_key
        print(f"Attempting registration for {user_address} using registrar account...")
        # Assumes register_user_on_chain takes (target_addr, name, role, registrar_key)
        receipt, error = register_user_on_chain(user_address, name, role, registrar_key)

        # 3. Handle result
        if receipt:
            flash(f'User {name} ({user_address}) registered successfully on the blockchain!', 'success')
            # Log the NEW user in immediately (Store THEIR key insecurely in session)
            session['user_address'] = user_address
            session['user_private_key'] = user_private_key # !!! INSECURE !!!
            session['user_role'] = role
            session['user_name'] = name
            # Construct the warning message showing the NEW USER'S private key
            key_warning = f'Your Address: {user_address}<br><strong>IMPORTANT - SAVE THIS PRIVATE KEY SECURELY (needed for login):</strong><br><span class="monospace">{user_private_key}</span>'
            flash(key_warning, 'warning') # Use 'warning' category for visibility
            transfer_ether(registrar_address, registrar_key, user_address, 0.3) # Optional: Transfer some ether to the new user
            return redirect(url_for('dashboard'))
        else:
            # Registration transaction failed
            flash(f'Blockchain registration failed: {error or "Unknown reason"}', 'danger')
            print(f"Registration TX failed for {user_address}. Error: {error}")
            return redirect(url_for('register')) # Go back on failure

    # If GET request
    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    """Handles user login using their private key."""
    if not w3 or not w3.is_connected():
        flash("Blockchain connection unavailable.", "danger")
        return render_template('login.html')

    if request.method == 'POST':
        private_key = request.form.get('private_key', '').strip() # Get and strip whitespace
        if not private_key:
            flash("Private key is required.", "warning")
            return redirect(url_for('login'))

        # Prepend 0x if missing (basic user convenience)
        if not private_key.startswith('0x'):
             private_key = '0x' + private_key

        # Validate key format and derive address
        try:
            account = w3.eth.account.from_key(private_key)
            user_address = account.address
        except ValueError:
             flash('Invalid private key format or length.', 'danger')
             return redirect(url_for('login'))
        except Exception as e:
             flash(f'An error occurred validating key: {e}', 'danger')
             print(f"Key validation error: {e}")
             traceback.print_exc()
             return redirect(url_for('login'))

        # Check registration status on chain
        if not contract:
             flash("Blockchain contract not initialized. Cannot verify user.", 'danger')
             return redirect(url_for('login'))

        print(f"Attempting login for address derived from key: {user_address}")
        user_info = get_user_info_from_chain(user_address)

        if user_info and user_info.get('isRegistered'):
            session['user_address'] = user_address
            session['user_private_key'] = private_key # !!! INSECURE !!!
            session['user_role'] = user_info['role']
            session['user_name'] = user_info['name']
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            if user_info is None:
                 flash('Login failed: Could not retrieve user information from the blockchain.', 'danger')
            else:
                 flash('Login failed: User not registered on blockchain or key is incorrect.', 'danger')
            print(f"Login failed for address {user_address}. UserInfo from chain: {user_info}")
            return redirect(url_for('login'))

    # If GET request
    return render_template('login.html')

# --- Dashboard Route ---

@app.route('/dashboard')
def dashboard():
    """Displays the appropriate dashboard, now fetching access lists."""
    user_address = get_current_user_address()
    user_key = get_current_user_key() # Needed to call new view functions

    if not user_address or not user_key: # Check key as well now
        flash("Please log in to view the dashboard.", "warning")
        return redirect(url_for('login'))

    connection_ok = w3 and w3.is_connected() and contract is not None
    if not connection_ok:
         flash("Blockchain connection issue. Dashboard functions may be limited or unavailable.", "danger")

    user_role = session.get('user_role')
    user_name = session.get('user_name')
    error_msg = None

    if user_role == 0: # Patient Dashboard
        records = []
        doctors_with_access_details = [] # List to hold {'address': ..., 'name': ...}

        if connection_ok:
            # Fetch patient's own records
            records, error = get_patient_records_list(user_address, user_address)
            if error: error_msg = f"Could not fetch records: {error}"; print(error_msg)

            # --- NEW: Fetch authorized doctors list ---
            doctor_addresses, doctors_error = get_authorized_doctors_from_chain(user_address, user_key)
            if doctors_error:
                 flash(f"Could not fetch authorized doctors list: {doctors_error}", "warning")
                 print(f"Error fetching doctors list for patient {user_address}: {doctors_error}")
            else:
                 # Fetch names for each doctor address
                 for doc_addr in doctor_addresses:
                     info = get_user_info_from_chain(doc_addr)
                     if info and info.get('isRegistered'): # Check if doctor info is valid
                         doctors_with_access_details.append({
                             'address': doc_addr,
                             'name': info.get('name', 'Unknown Doctor')
                         })
                     else:
                          # Add address even if name fetch fails, maybe show address only
                          doctors_with_access_details.append({'address': doc_addr, 'name': 'N/A (Info Error)'})
                          print(f"Warning: Could not get info for authorized doctor {doc_addr}")
            # --- End NEW ---
        else:
             error_msg = "Blockchain not connected. Cannot fetch patient data."

        return render_template('patient_dashboard.html',
                               user_address=user_address, user_name=user_name,
                               records=records,
                               doctors_with_access=doctors_with_access_details, # Pass populated list
                               error_msg=error_msg,
                               Config=Config)

    elif user_role == 1: # Doctor Dashboard
         accessible_patients_details = [] # List to hold {'address': ..., 'name': ...}
         if connection_ok:
             # --- NEW: Fetch accessible patients list ---
             patient_addresses, patients_error = get_accessible_patients_from_chain(user_address, user_key)
             if patients_error:
                  flash(f"Could not fetch accessible patients list: {patients_error}", "warning")
                  print(f"Error fetching patients list for doctor {user_address}: {patients_error}")
             else:
                  # Fetch names for each patient address
                  for patient_addr in patient_addresses:
                      info = get_user_info_from_chain(patient_addr)
                      if info and info.get('isRegistered'): # Check if patient info is valid
                          accessible_patients_details.append({
                              'address': patient_addr,
                              'name': info.get('name', 'Unknown Patient')
                          })
                      else:
                           accessible_patients_details.append({'address': patient_addr, 'name': 'N/A (Info Error)'})
                           print(f"Warning: Could not get info for accessible patient {patient_addr}")
             # --- End NEW ---
         else:
              error_msg = "Blockchain not connected. Cannot fetch doctor data."

         return render_template('doctor_dashboard.html',
                                user_address=user_address, user_name=user_name,
                                accessible_patients=accessible_patients_details, # Pass populated list
                                error_msg=error_msg,
                                Config=Config)

    else: # Unknown role
        flash("Error: Unknown user role. Logging out.", "danger")
        return redirect(url_for('logout'))

# --- Patient Action Routes ---

@app.route('/upload_record', methods=['POST'])
def upload_record():
    """Handles record upload BY a patient FOR themselves."""
    user_address = get_current_user_address()
    user_private_key = get_current_user_key()

    # Auth checks
    if not user_address or not user_private_key or session.get('user_role') != 0:
        flash("Unauthorized: Only logged-in patients can upload records.", "danger")
        return redirect(url_for('login'))
    if not contract:
         flash("Blockchain connection issue. Cannot upload record.", "danger")
         return redirect(url_for('dashboard'))

    # File checks
    record_type = request.form.get('record_type', 'General')
    if 'record_file' not in request.files:
        flash('No file part in request.', 'warning'); return redirect(url_for('dashboard'))
    file = request.files['record_file']
    if file.filename == '':
        flash('No file selected.', 'warning'); return redirect(url_for('dashboard'))
    if not allowed_file(file.filename):
        flash(f'File type not allowed.', 'warning'); return redirect(url_for('dashboard'))

    # Pinata Upload Logic
    cid = None
    pinata_api_key = Config.PINATA_API_KEY
    pinata_secret_key = Config.PINATA_SECRET_API_KEY
    pinata_api_url = "https://api.pinata.cloud/pinning/pinFileToIPFS"

    if not pinata_api_key or not pinata_secret_key:
        flash("Server configuration error: Pinata API keys not set.", "danger"); return redirect(url_for('dashboard'))

    try:
        # TODO: Encrypt file content before reading
        file_content = file.read()
        headers = {'pinata_api_key': pinata_api_key, 'pinata_secret_api_key': pinata_secret_key}
        files_payload = {'file': (secure_filename(file.filename), file_content)}
        print(f"Patient {user_address} uploading file '{secure_filename(file.filename)}' to Pinata...")
        response = requests.post(pinata_api_url, files=files_payload, headers=headers, timeout=120)
        response.raise_for_status()
        result = response.json()
        cid = result.get('IpfsHash')
        if not cid: raise Exception("Pinata upload failed: 'IpfsHash' not found.")
        print(f"File pinned via Pinata by patient. CID: {cid}")
    except Exception as e:
         # Consolidated error handling for Pinata upload
         error_message = f"Failed to upload file via Pinata: {e}"
         if isinstance(e, requests.exceptions.RequestException) and e.response is not None:
             error_message += f" | Status: {e.response.status_code}"
             if e.response.status_code == 401: error_message = "Pinata authentication failed. Check API keys."
         flash(error_message, "danger")
         print(f"Patient Upload Pinata Error: {e}")
         traceback.print_exc()
         return redirect(url_for('dashboard'))

    # Call Smart Contract
    if cid:
        # Patient uses their own key to add their record
        receipt, error = add_record_on_chain(user_address, cid, record_type, user_private_key)
        if receipt:
            flash(f"Record added successfully! IPFS CID: {cid}", "success")
        else:
            # Check if error indicates insufficient funds
            if error and 'insufficient funds' in error.lower():
                 flash(f"Blockchain Error: Insufficient funds in your account ({user_address[:6]}...) to pay for transaction gas.", "danger")
            else:
                 flash(f"Failed to add record reference to blockchain: {error or 'Unknown reason'}", "danger")
            # Consider unpinning?
    else:
         flash("Failed to get IPFS CID from Pinata, record not added.", "danger")

    return redirect(url_for('dashboard'))

@app.route('/grant_access', methods=['POST'])
def grant_access():
    """Handles patient granting access to a doctor."""
    user_address = get_current_user_address()
    user_private_key = get_current_user_key()

    # Auth & connection checks
    if not user_address or not user_private_key or session.get('user_role') != 0:
        flash("Unauthorized.", "danger"); return redirect(url_for('login'))
    if not contract:
         flash("Blockchain connection issue.", "danger"); return redirect(url_for('dashboard'))

    doctor_address = request.form.get('doctor_address')
    if not doctor_address or not Web3.is_address(doctor_address):
         flash("Invalid Doctor Ethereum address format.", "warning"); return redirect(url_for('dashboard'))

    # Check if target is a registered doctor
    doctor_info = get_user_info_from_chain(doctor_address)
    if not doctor_info or not doctor_info.get('isRegistered') or doctor_info.get('role') != 1:
        flash(f"Address provided is not registered as a Doctor.", "warning"); return redirect(url_for('dashboard'))

    # Patient uses their own key to grant access
    receipt, error = grant_access_on_chain(user_address, doctor_address, user_private_key)
    if receipt:
        flash(f"Access granted successfully to Dr. {doctor_info.get('name', doctor_address[:6])}", "success")
    else:
        if error and 'insufficient funds' in error.lower():
             flash(f"Blockchain Error: Insufficient funds in your account ({user_address[:6]}...) to pay for transaction gas.", "danger")
        else:
             flash(f"Failed to grant access on blockchain: {error or 'Unknown reason'}", "danger")

    return redirect(url_for('dashboard'))


@app.route('/revoke_access', methods=['POST'])
def revoke_access():
    """Handles patient revoking access from a doctor."""
    user_address = get_current_user_address()
    user_private_key = get_current_user_key()

    # Auth & connection checks
    if not user_address or not user_private_key or session.get('user_role') != 0:
        flash("Unauthorized.", "danger"); return redirect(url_for('login'))
    if not contract:
         flash("Blockchain connection issue.", "danger"); return redirect(url_for('dashboard'))

    doctor_address = request.form.get('doctor_address') # From hidden form input
    if not doctor_address or not Web3.is_address(doctor_address):
        flash("Invalid doctor address specified for revocation.", "warning"); return redirect(url_for('dashboard'))

    # Patient uses their own key to revoke access
    receipt, error = revoke_access_on_chain(user_address, doctor_address, user_private_key)
    if receipt:
        flash(f"Access revoked successfully for doctor {doctor_address[:6]}...", "success")
    else:
        if error and 'insufficient funds' in error.lower():
             flash(f"Blockchain Error: Insufficient funds in your account ({user_address[:6]}...) to pay for transaction gas.", "danger")
        else:
             flash(f"Failed to revoke access on blockchain: {error or 'Unknown reason'}", "danger")

    return redirect(url_for('dashboard'))


# --- Doctor Action Routes ---

@app.route('/doctor/add_record/<string:patient_address>', methods=['POST'])
def doctor_add_record_for_patient(patient_address):
    """Handles record upload BY a doctor FOR a specific patient."""
    doctor_address = get_current_user_address()
    doctor_private_key = get_current_user_key()

    # 1. Authentication & Authorization
    if not doctor_address or not doctor_private_key or session.get('user_role') != 1:
        flash("Unauthorized: Only logged-in doctors can perform this action.", "danger")
        return redirect(url_for('login'))
    if not contract:
         flash("Blockchain connection issue. Cannot add record.", "danger")
         return redirect(url_for('dashboard'))
    if not Web3.is_address(patient_address):
         flash("Invalid patient address specified.", "warning")
         return redirect(url_for('dashboard'))

    # Verify doctor has access to this specific patient BEFORE processing upload
    if not check_access_on_chain(patient_address, doctor_address):
         flash("Authorization Error: You do not have permission to add records for this patient.", "danger")
         return redirect(url_for('dashboard'))

    # 2. File Handling
    record_type = request.form.get('record_type', 'General Observation') # Default type
    if 'record_file' not in request.files:
        flash('No file part in request.', 'warning'); return redirect(url_for('dashboard'))
    file = request.files['record_file']
    if file.filename == '':
        flash('No file selected.', 'warning'); return redirect(url_for('dashboard'))
    if not allowed_file(file.filename):
        flash(f'File type not allowed.', 'warning'); return redirect(url_for('dashboard'))

    # 3. Off-Chain Storage (Pinata)
    cid = None
    pinata_api_key = Config.PINATA_API_KEY
    pinata_secret_key = Config.PINATA_SECRET_API_KEY
    pinata_api_url = "https://api.pinata.cloud/pinning/pinFileToIPFS"

    if not pinata_api_key or not pinata_secret_key:
        flash("Server configuration error: Pinata API keys not set.", "danger"); return redirect(url_for('dashboard'))

    try:
        # TODO: Encrypt file content
        file_content = file.read()
        headers = {'pinata_api_key': pinata_api_key, 'pinata_secret_api_key': pinata_secret_key}
        files_payload = {'file': (secure_filename(file.filename), file_content)}
        print(f"Doctor {doctor_address} uploading file '{secure_filename(file.filename)}' to Pinata for patient {patient_address}...")
        response = requests.post(pinata_api_url, files=files_payload, headers=headers, timeout=120)
        response.raise_for_status()
        result = response.json()
        cid = result.get('IpfsHash')
        if not cid: raise Exception("Pinata upload failed: 'IpfsHash' not found.")
        print(f"File pinned via Pinata by doctor. CID: {cid}")
    except Exception as e:
         # Consolidated error handling for Pinata upload
         error_message = f"Failed to upload file via Pinata: {e}"
         if isinstance(e, requests.exceptions.RequestException) and e.response is not None:
             error_message += f" | Status: {e.response.status_code}"
             if e.response.status_code == 401: error_message = "Pinata authentication failed. Check API keys."
         flash(error_message, "danger")
         print(f"Doctor Upload Pinata Error: {e}")
         traceback.print_exc()
         return redirect(url_for('dashboard')) # Or redirect to specific patient view if available

    # 4. Call Smart Contract Util Function
    if cid:
        print(f"Calling add_record_for_patient_by_doctor util function...")
        # Doctor uses THEIR OWN key to add record FOR patient
        receipt, error = add_record_for_patient_by_doctor(
            doctor_address=doctor_address,
            doctor_private_key=doctor_private_key,
            patient_address=patient_address,
            data_hash=cid,
            record_type=record_type
        )
        if receipt:
            flash(f"Record added successfully for patient {patient_address[:6]}...! CID: {cid}", "success")
        else:
            # Handle potential contract error (e.g., function not found or insufficient funds for DOCTOR)
            error_msg = f"Failed to add record to blockchain for patient: {error or 'Unknown reason'}"
            if error and 'insufficient funds' in error.lower():
                 error_msg = f"Blockchain Error: Insufficient funds in YOUR (doctor's) account ({doctor_address[:6]}...) to pay for transaction gas."
            elif error and 'function not found' in error.lower():
                 error_msg = "Contract Error: The required 'addRecordForPatient' function may be missing. Ensure the correct contract version is deployed."

            flash(error_msg, "danger")
            print(error_msg)
            # Consider unpinning?
    else:
         flash("Failed to get IPFS CID from Pinata, record not added to blockchain.", "danger")

    # Redirect back to doctor dashboard (ideally would refresh the patient's record view)
    return redirect(url_for('dashboard'))


# --- API Endpoints ---

@app.route('/api/doctor/get_patient_records/<string:patient_address>')
def api_doctor_get_patient_records(patient_address):
    """API endpoint for logged-in doctors to fetch records of patients who granted them access."""
    doctor_address = get_current_user_address()

    # Auth & validation checks
    if not doctor_address or session.get('user_role') != 1:
        return jsonify({"error": "Unauthorized: Doctor access required"}), 401
    if not contract:
        return jsonify({"error": "Blockchain contract connection unavailable"}), 503
    if not Web3.is_address(patient_address):
        return jsonify({"error": "Invalid patient address format"}), 400

    # Fetch Records (utils function includes access check)
    print(f"Doctor {doctor_address} requesting records via API for patient {patient_address}")
    records, error = get_patient_records_list(patient_address, doctor_address)

    # Return Response
    if error:
        if error == "Access Denied":
             print(f"API Access Denied: Doctor {doctor_address} cannot access records for patient {patient_address}")
             return jsonify({"error": "Access Denied"}), 403
        else:
             print(f"API Error fetching patient records: {error}")
             return jsonify({"error": f"Could not fetch records: {error}"}), 500
    else:
        print(f"API returning {len(records)} records for patient {patient_address}")
        # Add readable timestamp before returning
        for record in records:
            record['timestamp_str'] = timestamp_to_datetime_filter(record['timestamp'])
        return jsonify({"records": records})


@app.route('/view_record/<string:patient_address>/<string:record_hash>')
def view_record_data(patient_address, record_hash):
    """API endpoint (called by JS) to fetch record data from off-chain storage via Gateway."""
    user_address = get_current_user_address() # Could be patient or doctor

    # Auth & validation checks
    if not user_address: return jsonify({"error": "Authentication required"}), 401
    if not contract: return jsonify({"error": "Blockchain connection unavailable"}), 503
    if not Web3.is_address(patient_address): return jsonify({"error": "Invalid patient address format"}), 400
    if not record_hash or len(record_hash) < 40: return jsonify({"error": "Invalid record hash format"}), 400

    # Authorization Check (Patient self OR Doctor with access)
    has_access = False
    if user_address == patient_address:
        has_access = True
    else:
        # If not the patient, check if they are a doctor with access
        # We could check role from session, but checking on chain is more definitive
        has_access = check_access_on_chain(patient_address, user_address)

    if not has_access:
        print(f"Access Denied: User {user_address} tried view_record on {record_hash} for patient {patient_address}")
        return jsonify({"error": "Access Denied"}), 403

    # Fetch from IPFS Gateway
    gateway_base_url = Config.IPFS_GATEWAY_URL
    if not gateway_base_url: return jsonify({"error": "Data storage gateway not configured"}), 500
    if not gateway_base_url.endswith('/'): gateway_base_url += '/'
    fetch_url = f"{gateway_base_url}{record_hash}"

    print(f"Fetching record data from Gateway: {fetch_url}")
    try:
        response = requests.get(fetch_url, timeout=60)
        response.raise_for_status()
        # TODO: Implement decryption here
        decrypted_content = response.content.decode('utf-8', errors='ignore') # DEMO: Assume text
        return jsonify({"data": decrypted_content})
    except requests.exceptions.RequestException as e:
        # Consolidated error handling for gateway fetch
        error_message = f"Failed to fetch data from gateway: {e}"
        status_code = 502 # Bad Gateway default
        if e.response is not None:
            status_code = e.response.status_code
            error_message += f" | Status: {status_code}"
            if status_code == 404: error_message = f"Data not found for hash {record_hash}"
        elif isinstance(e, requests.exceptions.Timeout):
            status_code = 504 # Gateway Timeout
            error_message = "Timeout fetching data from gateway"
        elif isinstance(e, requests.exceptions.ConnectionError):
             status_code = 504
             error_message = f"Could not connect to data storage gateway at {gateway_base_url}"

        print(f"Gateway Fetch Error: {error_message}")
        return jsonify({"error": error_message}), status_code
    except Exception as e:
        print(f"Error processing gateway data {record_hash}: {e}")
        traceback.print_exc()
        return jsonify({"error": f"Error processing stored data"}), 500




# --- Main Execution ---
if __name__ == '__main__':
    # Initial checks on startup
    startup_warnings = []
    if not w3 or not w3.is_connected(): startup_warnings.append("Web3 connection FAILED.")
    if not Config.CONTRACT_ADDRESS: startup_warnings.append("CONTRACT_ADDRESS not set in .env.")
    elif not contract: startup_warnings.append("Contract instance FAILED to initialize (check address/ABI/connection).")
    if not Config.SERVER_ACCOUNT_PRIVATE_KEY: startup_warnings.append("Registrar key (DEPLOYER_PRIVATE_KEY) not set in .env (registration will fail).")
    if not Config.PINATA_API_KEY or not Config.PINATA_SECRET_API_KEY: startup_warnings.append("Pinata keys not set (file uploads will fail).")

    if startup_warnings:
        print("\n--- STARTUP WARNINGS ---")
        for warning in startup_warnings:
            print(f"- {warning}")
        print("----------------------\n")

    # Set debug=False for production deployment
    app.run(host='0.0.0.0', port=5000, debug=True)