// SPDX-License-Identifier: MIT
// Updated: 2025-05-02
pragma solidity ^0.8.9; // Or your chosen compatible version (e.g., 0.8.17)

/**
 * @title MedicalRecords Contract
 * @dev Manages user registration, record metadata, and access permissions.
 * Includes on-chain lists for doctor's accessible patients and patient's authorized doctors.
 * WARNING: Maintaining these on-chain lists can be gas-intensive.
 */
contract MedicalRecords {
    // --- Structs ---
    struct Record {
        string dataHash;
        uint256 timestamp;
        address uploadedBy;
        string recordType;
    }

    struct User {
        string name;
        UserRole role;
        bool isRegistered;
    }

    enum UserRole { Patient, Doctor }

    // --- State Variables ---
    address public owner;

    mapping(address => User) public users;
    mapping(address => Record[]) public patientRecords;
    mapping(address => mapping(address => bool)) public accessPermissions; // Patient -> Doctor -> hasAccess?
    mapping(string => bool) private recordHashExists;

    // --- NEW: On-Chain Access Lists ---
    // Doctor address -> List of patient addresses they can access
    mapping(address => address[]) public doctorToAccessiblePatients;
    // Patient address -> List of doctor addresses authorized to access their records
    mapping(address => address[]) public patientToAuthorizedDoctors;

    // Helper mappings to store the index of an item in the array for efficient removal (O(1) swap-and-pop)
    // Doctor -> Patient -> Index in doctorToAccessiblePatients[doctor] array
    mapping(address => mapping(address => uint)) private doctorPatientIndex;
    // Patient -> Doctor -> Index in patientToAuthorizedDoctors[patient] array
    mapping(address => mapping(address => uint)) private patientDoctorIndex;
    // --- End NEW ---

    // --- Events ---
    event UserRegistered(address indexed userAddress, string name, UserRole role);
    event RecordAdded(address indexed patient, string dataHash, address indexed uploadedBy);
    event AccessGranted(address indexed patient, address indexed doctor);
    event AccessRevoked(address indexed patient, address indexed doctor);

    // --- Modifiers ---
    modifier onlyOwner() { /* ... */ require(msg.sender == owner, "Only owner"); _; }
    modifier onlyRegisteredUser() { /* ... */ require(users[msg.sender].isRegistered, "User not registered"); _; }
    modifier onlyPatient() { /* ... */ require(users[msg.sender].role == UserRole.Patient, "Only patients"); _; }
    modifier onlyDoctor() { /* ... */ require(users[msg.sender].role == UserRole.Doctor, "Only doctors"); _; }
    modifier hasAccess(address _patient) { /* ... */ require(msg.sender == _patient || accessPermissions[_patient][msg.sender], "Access denied"); _; }

    // --- Constructor ---
    constructor() {
        owner = msg.sender;
    }

    // --- User Management ---
    function registerUser(address userAddress, string memory _name, UserRole _role) public /* onlyRegistrar or similar if needed */ {
        // Using registrar pattern where a pre-funded account calls this
        require(userAddress != address(0), "Zero address");
        require(!users[userAddress].isRegistered, "User already registered");
        users[userAddress] = User(_name, _role, true);
        emit UserRegistered(userAddress, _name, _role);
    }

    // --- Record Management ---
    // Patient adds own record
    function addRecord(string memory _dataHash, string memory _recordType) public onlyPatient onlyRegisteredUser {
        require(!recordHashExists[_dataHash], "Record hash exists");
        patientRecords[msg.sender].push(Record(_dataHash, block.timestamp, msg.sender, _recordType));
        recordHashExists[_dataHash] = true;
        emit RecordAdded(msg.sender, _dataHash, msg.sender);
    }

    // Doctor adds record FOR patient (Requires this function to exist)
    function addRecordForPatient(address _patient, string memory _dataHash, string memory _recordType)
        public
        onlyDoctor // Caller must be a doctor
        hasAccess(_patient) // Doctor must have access to the patient
    {
        require(users[_patient].isRegistered && users[_patient].role == UserRole.Patient, "Target not patient");
        require(!recordHashExists[_dataHash], "Record hash exists");
        patientRecords[_patient].push(Record(_dataHash, block.timestamp, msg.sender, _recordType)); // Add to patient's list, record doctor as uploader
        recordHashExists[_dataHash] = true;
        emit RecordAdded(_patient, _dataHash, msg.sender);
    }

    // --- Access Control ---
    function grantAccess(address _doctor) public onlyPatient onlyRegisteredUser {
        require(users[_doctor].isRegistered && users[_doctor].role == UserRole.Doctor, "Target not doctor");
        require(!accessPermissions[msg.sender][_doctor], "Access already granted");

        accessPermissions[msg.sender][_doctor] = true;

        // --- NEW: Add to on-chain lists ---
        // Add doctor to patient's list
        patientToAuthorizedDoctors[msg.sender].push(_doctor);
        patientDoctorIndex[msg.sender][_doctor] = patientToAuthorizedDoctors[msg.sender].length - 1; // Store index

        // Add patient to doctor's list
        doctorToAccessiblePatients[_doctor].push(msg.sender);
        doctorPatientIndex[_doctor][msg.sender] = doctorToAccessiblePatients[_doctor].length - 1; // Store index
        // --- End NEW ---

        emit AccessGranted(msg.sender, _doctor);
    }

    function revokeAccess(address _doctor) public onlyPatient onlyRegisteredUser {
        require(users[_doctor].isRegistered && users[_doctor].role == UserRole.Doctor, "Target not doctor");
        require(accessPermissions[msg.sender][_doctor], "Access not granted"); // Check access exists

        accessPermissions[msg.sender][_doctor] = false;

        // --- NEW: Remove from on-chain lists using swap-and-pop ---
        // Remove doctor from patient's list
        uint doctorIndex = patientDoctorIndex[msg.sender][_doctor];
        address lastDoctor = patientToAuthorizedDoctors[msg.sender][patientToAuthorizedDoctors[msg.sender].length - 1];
        patientToAuthorizedDoctors[msg.sender][doctorIndex] = lastDoctor; // Move last element to the removed spot
        patientDoctorIndex[msg.sender][lastDoctor] = doctorIndex; // Update index of the moved element
        patientToAuthorizedDoctors[msg.sender].pop(); // Remove the last element
        delete patientDoctorIndex[msg.sender][_doctor]; // Clean up index mapping for removed doctor

        // Remove patient from doctor's list
        uint patientIndex = doctorPatientIndex[_doctor][msg.sender];
        address lastPatient = doctorToAccessiblePatients[_doctor][doctorToAccessiblePatients[_doctor].length - 1];
        doctorToAccessiblePatients[_doctor][patientIndex] = lastPatient; // Move last element
        doctorPatientIndex[_doctor][lastPatient] = patientIndex; // Update index
        doctorToAccessiblePatients[_doctor].pop(); // Remove last
        delete doctorPatientIndex[_doctor][msg.sender]; // Clean up index
        // --- End NEW ---

        emit AccessRevoked(msg.sender, _doctor);
    }

    // --- View Functions ---
    function getRecord(address _patient, uint _index) public view returns (string memory dataHash, uint256 timestamp, address uploadedBy, string memory recordType) {
        // Removed hasAccess modifier here - access check done off-chain before calling loops
        require(_patient != address(0), "Invalid patient address");
        require(_index < patientRecords[_patient].length, "Record index out of bounds");
        Record storage record = patientRecords[_patient][_index];
        return (record.dataHash, record.timestamp, record.uploadedBy, record.recordType);
    }

    function getRecordsCount(address _patient) public view returns (uint) {
        // Removed hasAccess modifier here
        require(_patient != address(0), "Invalid patient address");
        return patientRecords[_patient].length;
    }

    function checkAccess(address _patient, address _doctor) public view returns (bool) {
        // Simple view, no modifier needed
        return accessPermissions[_patient][_doctor];
    }

    function getUserInfo(address _userAddress) public view returns (string memory name, UserRole role, bool isRegistered) {
        User storage user = users[_userAddress];
        return (user.name, user.role, user.isRegistered);
    }

    // --- NEW: View functions for access lists ---
    /**
     * @dev Gets the list of patient addresses accessible by the calling doctor.
     * @return An array of patient addresses.
     */
    function getAccessiblePatients() public view onlyDoctor returns (address[] memory) {
        return doctorToAccessiblePatients[msg.sender];
    }

    /**
     * @dev Gets the list of doctor addresses authorized by the calling patient.
     * @return An array of doctor addresses.
     */
    function getAuthorizedDoctors() public view onlyPatient returns (address[] memory) {
        return patientToAuthorizedDoctors[msg.sender];
    }
    // --- End NEW ---

}
