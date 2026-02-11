// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title ProxyContract
 * @notice A minimal transparent proxy implementation for testing proxy detection
 * @dev Uses the EIP-1967 storage slots for implementation and admin
 *
 * This contract demonstrates:
 * - Delegatecall pattern for proxy
 * - Initializable pattern (instead of constructor)
 * - Storage layout considerations (EIP-1967 slots)
 * - Admin and implementation slot management
 */

/**
 * @title Initializable
 * @notice Manual implementation of initializable pattern
 */
abstract contract Initializable {
    /**
     * @dev Storage slot for initialization state
     * This is keccak256("eip1967.proxy.initialized") - 1
     */
    bytes32 private constant _INITIALIZED_SLOT =
        0x4a204f6c206174206c656173742074686973206973206e6f742074686520696e;

    error AlreadyInitialized();
    error NotInitializing();

    modifier initializer() {
        bool initialized = _getInitialized();
        if (initialized) revert AlreadyInitialized();
        _setInitialized(true);
        _;
    }

    modifier onlyInitializing() {
        // For nested initializations
        _;
    }

    function _getInitialized() internal view returns (bool) {
        bool initialized;
        assembly {
            initialized := sload(_INITIALIZED_SLOT)
        }
        return initialized;
    }

    function _setInitialized(bool value) private {
        assembly {
            sstore(_INITIALIZED_SLOT, value)
        }
    }
}

/**
 * @title StorageSlot
 * @notice Helper library for reading/writing EIP-1967 storage slots
 */
library StorageSlot {
    struct AddressSlot {
        address value;
    }

    function getAddressSlot(bytes32 slot) internal pure returns (AddressSlot storage r) {
        assembly {
            r.slot := slot
        }
    }
}

/**
 * @title ProxyContract
 * @notice Transparent proxy that delegates all calls to an implementation contract
 */
contract ProxyContract is Initializable {
    /**
     * @dev EIP-1967 implementation slot
     * bytes32(uint256(keccak256("eip1967.proxy.implementation")) - 1)
     */
    bytes32 private constant _IMPLEMENTATION_SLOT =
        0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;

    /**
     * @dev EIP-1967 admin slot
     * bytes32(uint256(keccak256("eip1967.proxy.admin")) - 1)
     */
    bytes32 private constant _ADMIN_SLOT =
        0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103;

    /**
     * @dev EIP-1967 beacon slot (for beacon proxy detection)
     * bytes32(uint256(keccak256("eip1967.proxy.beacon")) - 1)
     */
    bytes32 private constant _BEACON_SLOT =
        0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50;

    event Upgraded(address indexed implementation);
    event AdminChanged(address previousAdmin, address newAdmin);

    error NotAdmin();
    error InvalidImplementation();
    error DelegateCallFailed();

    modifier onlyAdmin() {
        if (msg.sender != _getAdmin()) revert NotAdmin();
        _;
    }

    /**
     * @notice Initialize the proxy with implementation and admin
     * @param implementation_ Initial implementation address
     * @param admin_ Admin address
     * @param data_ Initialization calldata for the implementation
     */
    function initialize(
        address implementation_,
        address admin_,
        bytes calldata data_
    ) external initializer {
        _setImplementation(implementation_);
        _setAdmin(admin_);

        if (data_.length > 0) {
            // Initialize the implementation
            (bool success, ) = implementation_.delegatecall(data_);
            if (!success) revert DelegateCallFailed();
        }
    }

    /**
     * @notice Upgrade to a new implementation
     * @param newImplementation Address of new implementation
     */
    function upgradeTo(address newImplementation) external onlyAdmin {
        _setImplementation(newImplementation);
        emit Upgraded(newImplementation);
    }

    /**
     * @notice Upgrade and call in a single transaction
     * @param newImplementation Address of new implementation
     * @param data Calldata for initialization
     */
    function upgradeToAndCall(address newImplementation, bytes calldata data)
        external
        onlyAdmin
    {
        _setImplementation(newImplementation);
        emit Upgraded(newImplementation);

        if (data.length > 0) {
            (bool success, ) = newImplementation.delegatecall(data);
            if (!success) revert DelegateCallFailed();
        }
    }

    /**
     * @notice Change the admin
     * @param newAdmin New admin address
     */
    function changeAdmin(address newAdmin) external onlyAdmin {
        address oldAdmin = _getAdmin();
        _setAdmin(newAdmin);
        emit AdminChanged(oldAdmin, newAdmin);
    }

    /**
     * @notice Get the current implementation address
     */
    function implementation() external view returns (address) {
        return _getImplementation();
    }

    /**
     * @notice Get the current admin address
     */
    function admin() external view returns (address) {
        return _getAdmin();
    }

    // ========================================================================
    // Internal functions
    // ========================================================================

    function _getImplementation() internal view returns (address) {
        return StorageSlot.getAddressSlot(_IMPLEMENTATION_SLOT).value;
    }

    function _setImplementation(address newImplementation) private {
        if (newImplementation.code.length == 0) revert InvalidImplementation();
        StorageSlot.getAddressSlot(_IMPLEMENTATION_SLOT).value = newImplementation;
    }

    function _getAdmin() internal view returns (address) {
        return StorageSlot.getAddressSlot(_ADMIN_SLOT).value;
    }

    function _setAdmin(address newAdmin) private {
        StorageSlot.getAddressSlot(_ADMIN_SLOT).value = newAdmin;
    }

    /**
     * @dev Delegates execution to the implementation contract
     */
    function _delegate(address impl) internal virtual {
        assembly {
            // Copy msg.data
            calldatacopy(0, 0, calldatasize())

            // Delegatecall to implementation
            let result := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)

            // Copy returndata
            returndatacopy(0, 0, returndatasize())

            switch result
            case 0 {
                revert(0, returndatasize())
            }
            default {
                return(0, returndatasize())
            }
        }
    }

    /**
     * @dev Fallback function that delegates all calls to the implementation
     */
    fallback() external payable {
        _delegate(_getImplementation());
    }

    /**
     * @dev Receive function to accept ETH
     */
    receive() external payable {
        _delegate(_getImplementation());
    }
}

/**
 * @title ImplementationV1
 * @notice Sample implementation contract for testing
 */
contract ImplementationV1 is Initializable {
    // Storage layout must be consistent across upgrades
    uint256 public value;
    address public owner;
    mapping(address => uint256) public balances;

    // Gap for future storage variables
    uint256[47] private __gap;

    event ValueChanged(uint256 oldValue, uint256 newValue);

    error NotOwner();

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    function initialize(address owner_) external initializer {
        owner = owner_;
        value = 0;
    }

    function setValue(uint256 newValue) external onlyOwner {
        uint256 oldValue = value;
        value = newValue;
        emit ValueChanged(oldValue, newValue);
    }

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        balances[msg.sender] -= amount;
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
    }

    function version() external pure returns (string memory) {
        return "1.0.0";
    }
}

/**
 * @title ImplementationV2
 * @notice Upgraded implementation with new features
 */
contract ImplementationV2 is Initializable {
    // Storage layout must match V1
    uint256 public value;
    address public owner;
    mapping(address => uint256) public balances;

    // New storage in V2 (uses gap from V1)
    uint256 public multiplier;

    // Reduced gap
    uint256[46] private __gap;

    event ValueChanged(uint256 oldValue, uint256 newValue);
    event MultiplierChanged(uint256 oldMultiplier, uint256 newMultiplier);

    error NotOwner();

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    // No initialize - storage is preserved from V1
    function initializeV2(uint256 multiplier_) external {
        require(multiplier == 0, "Already initialized V2");
        multiplier = multiplier_;
    }

    function setValue(uint256 newValue) external onlyOwner {
        uint256 oldValue = value;
        value = newValue * multiplier;
        emit ValueChanged(oldValue, value);
    }

    function setMultiplier(uint256 newMultiplier) external onlyOwner {
        uint256 oldMultiplier = multiplier;
        multiplier = newMultiplier;
        emit MultiplierChanged(oldMultiplier, newMultiplier);
    }

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        balances[msg.sender] -= amount;
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
    }

    function version() external pure returns (string memory) {
        return "2.0.0";
    }
}

/**
 * @title BeaconProxy
 * @notice A beacon proxy that gets its implementation from a beacon contract
 * @dev Used to test beacon proxy detection
 */
contract Beacon {
    address private _implementation;
    address private _owner;

    event Upgraded(address indexed implementation);

    error NotOwner();
    error InvalidImplementation();

    constructor(address implementation_) {
        _implementation = implementation_;
        _owner = msg.sender;
    }

    function implementation() external view returns (address) {
        return _implementation;
    }

    function upgradeTo(address newImplementation) external {
        if (msg.sender != _owner) revert NotOwner();
        if (newImplementation.code.length == 0) revert InvalidImplementation();
        _implementation = newImplementation;
        emit Upgraded(newImplementation);
    }
}
