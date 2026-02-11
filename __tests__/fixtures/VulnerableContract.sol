// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title VulnerableContract
 * @notice A contract with intentional vulnerabilities for testing purposes
 * @dev DO NOT USE IN PRODUCTION - Contains known security issues
 *
 * Vulnerabilities included:
 * - SWC-103: Floating Pragma
 * - SWC-104: Unchecked Call Return Value
 * - SWC-105: Unprotected Ether Withdrawal
 * - SWC-106: Unprotected SELFDESTRUCT
 * - SWC-107: Reentrancy
 * - SWC-108: State Variable Default Visibility
 * - SWC-112: Delegatecall to Untrusted Callee
 * - SWC-115: Authorization through tx.origin
 * - SWC-116: Block values as proxy for time
 * - SWC-119: Variable Shadowing
 * - SWC-120: Weak Randomness
 * - SWC-128: DoS with Block Gas Limit
 * - SWC-131: Unused Variables
 */
contract VulnerableContract {
    address public owner;
    mapping(address => uint256) public balances;
    mapping(address => bool) public isAdmin;

    uint256 public totalDeposits;
    bool public paused;

    // SWC-119: This variable will be shadowed in processWithShadowing()
    uint256 public result;

    // SWC-108: State variable default visibility (internal by default)
    uint256 secretValue;
    uint256 uninitializedThreshold; // Also uninitialized - defaults to 0

    event Deposit(address indexed user, uint256 amount);
    event Withdrawal(address indexed user, uint256 amount);
    event AdminAdded(address indexed admin);

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    modifier notPaused() {
        require(!paused, "Contract is paused");
        _;
    }

    constructor() {
        owner = msg.sender;
        isAdmin[msg.sender] = true;
    }

    // SWC-115: Authorization through tx.origin
    function addAdmin(address _admin) external {
        require(tx.origin == owner, "Not authorized");
        isAdmin[_admin] = true;
        emit AdminAdded(_admin);
    }

    function deposit() external payable notPaused {
        require(msg.value > 0, "Must deposit something");
        balances[msg.sender] += msg.value;
        totalDeposits += msg.value;
        emit Deposit(msg.sender, msg.value);
    }

    // SWC-107: Reentrancy vulnerability
    function withdraw(uint256 _amount) external notPaused {
        require(balances[msg.sender] >= _amount, "Insufficient balance");

        // Vulnerable: state update after external call
        (bool success, ) = msg.sender.call{value: _amount}("");
        require(success, "Transfer failed");

        balances[msg.sender] -= _amount;
        totalDeposits -= _amount;

        emit Withdrawal(msg.sender, _amount);
    }

    // SWC-105: Unprotected Ether withdrawal
    function emergencyWithdraw() external {
        uint256 balance = address(this).balance;
        (bool success, ) = msg.sender.call{value: balance}("");
        require(success, "Transfer failed");
    }

    // SWC-104: Unchecked return value
    function unsafeTransfer(address _token, address _to, uint256 _amount) external onlyOwner {
        // Missing return value check
        IERC20(_token).transfer(_to, _amount);
    }

    // SWC-120: Weak source of randomness
    function getRandomNumber() public view returns (uint256) {
        return uint256(keccak256(abi.encodePacked(
            block.timestamp,
            block.prevrandao,
            msg.sender
        )));
    }

    // SWC-116: Block values as proxy for time
    function isExpired(uint256 _deadline) public view returns (bool) {
        return block.timestamp == _deadline; // Strict equality with timestamp
    }

    // SWC-128: DoS with block gas limit
    function distributeRewards(address[] calldata _recipients, uint256[] calldata _amounts)
        external
        onlyOwner
    {
        require(_recipients.length == _amounts.length, "Length mismatch");

        for (uint256 i = 0; i < _recipients.length; i++) {
            (bool success, ) = _recipients[i].call{value: _amounts[i]}("");
            require(success, "Transfer failed");
        }
    }

    // SWC-112: Delegatecall to untrusted callee
    function executeDelegate(address _target, bytes calldata _data)
        external
        onlyOwner
        returns (bytes memory)
    {
        (bool success, bytes memory result) = _target.delegatecall(_data);
        require(success, "Delegatecall failed");
        return result;
    }

    // SWC-106: Unprotected selfdestruct
    function destroy() external {
        selfdestruct(payable(msg.sender));
    }

    // SWC-131: Unused variable
    function processData(uint256 _input) external pure returns (uint256) {
        uint256 unusedVar = _input * 2;
        uint256 output = _input + 1;
        return output;
    }

    // SWC-119: Variable Shadowing - local variable shadows state variable 'result'
    function processWithShadowing(uint256 _input) external pure returns (uint256) {
        // VULNERABLE: This shadows the state variable 'result'
        uint256 result = _input * 3;
        return result;
    }

    // SWC-100: Function should be external instead of public
    // Public uses more gas when called externally
    function publicInsteadOfExternal(uint256 _value) public pure returns (uint256) {
        return _value * 2;
    }

    // Missing zero address check
    function setOwner(address _newOwner) external onlyOwner {
        owner = _newOwner;
    }

    function pause() external onlyOwner {
        paused = true;
    }

    function unpause() external onlyOwner {
        paused = false;
    }

    function getBalance(address _user) external view returns (uint256) {
        return balances[_user];
    }

    receive() external payable {
        balances[msg.sender] += msg.value;
        totalDeposits += msg.value;
    }
}

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}
