// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

/**
 * @title SafeContract
 * @notice A contract demonstrating security best practices
 * @dev Uses OpenZeppelin libraries for common security patterns
 */
contract SafeContract is ReentrancyGuard, Ownable, Pausable {
    using SafeERC20 for IERC20;

    mapping(address => uint256) private _balances;
    mapping(address => bool) private _admins;

    uint256 private _totalDeposits;

    uint256 public constant MIN_DEPOSIT = 0.01 ether;
    uint256 public constant MAX_DEPOSIT = 100 ether;

    event Deposit(address indexed user, uint256 amount);
    event Withdrawal(address indexed user, uint256 amount);
    event AdminStatusChanged(address indexed admin, bool status);

    error ZeroAddress();
    error InsufficientBalance(uint256 requested, uint256 available);
    error DepositTooSmall(uint256 amount, uint256 minimum);
    error DepositTooLarge(uint256 amount, uint256 maximum);
    error TransferFailed();

    modifier validAddress(address _addr) {
        if (_addr == address(0)) revert ZeroAddress();
        _;
    }

    constructor(address initialOwner) Ownable(initialOwner) {
        _admins[initialOwner] = true;
    }

    /**
     * @notice Add or remove an admin
     * @param _admin Address to modify
     * @param _status True to add, false to remove
     */
    function setAdmin(address _admin, bool _status)
        external
        onlyOwner
        validAddress(_admin)
    {
        _admins[_admin] = _status;
        emit AdminStatusChanged(_admin, _status);
    }

    /**
     * @notice Deposit ETH into the contract
     */
    function deposit() external payable whenNotPaused {
        if (msg.value < MIN_DEPOSIT) {
            revert DepositTooSmall(msg.value, MIN_DEPOSIT);
        }
        if (msg.value > MAX_DEPOSIT) {
            revert DepositTooLarge(msg.value, MAX_DEPOSIT);
        }

        _balances[msg.sender] += msg.value;
        _totalDeposits += msg.value;

        emit Deposit(msg.sender, msg.value);
    }

    /**
     * @notice Withdraw ETH using checks-effects-interactions pattern
     * @param _amount Amount to withdraw
     */
    function withdraw(uint256 _amount) external nonReentrant whenNotPaused {
        uint256 balance = _balances[msg.sender];

        if (balance < _amount) {
            revert InsufficientBalance(_amount, balance);
        }

        // Effects before interactions
        _balances[msg.sender] = balance - _amount;
        _totalDeposits -= _amount;

        // Interaction last
        (bool success, ) = msg.sender.call{value: _amount}("");
        if (!success) revert TransferFailed();

        emit Withdrawal(msg.sender, _amount);
    }

    /**
     * @notice Safe ERC20 transfer
     * @param _token Token address
     * @param _to Recipient address
     * @param _amount Amount to transfer
     */
    function safeTokenTransfer(
        address _token,
        address _to,
        uint256 _amount
    )
        external
        onlyOwner
        validAddress(_token)
        validAddress(_to)
    {
        IERC20(_token).safeTransfer(_to, _amount);
    }

    /**
     * @notice Check expiration with tolerance
     * @param _deadline Deadline timestamp
     * @param _tolerance Tolerance in seconds
     */
    function isExpired(uint256 _deadline, uint256 _tolerance)
        public
        view
        returns (bool)
    {
        return block.timestamp > _deadline + _tolerance;
    }

    /**
     * @notice Distribute rewards with pagination to prevent DoS
     * @param _recipients Array of recipient addresses
     * @param _amounts Array of amounts
     * @param _offset Starting index
     * @param _limit Maximum recipients to process
     */
    function distributeRewards(
        address[] calldata _recipients,
        uint256[] calldata _amounts,
        uint256 _offset,
        uint256 _limit
    )
        external
        onlyOwner
        nonReentrant
    {
        require(_recipients.length == _amounts.length, "Length mismatch");

        uint256 end = _offset + _limit;
        if (end > _recipients.length) {
            end = _recipients.length;
        }

        for (uint256 i = _offset; i < end; ) {
            address recipient = _recipients[i];
            if (recipient != address(0)) {
                (bool success, ) = recipient.call{value: _amounts[i]}("");
                // Continue even if one transfer fails (pull pattern would be better)
                if (success) {
                    emit Withdrawal(recipient, _amounts[i]);
                }
            }
            unchecked { ++i; }
        }
    }

    /**
     * @notice Transfer ownership with zero address check
     * @param newOwner New owner address
     */
    function transferOwnership(address newOwner)
        public
        override
        onlyOwner
        validAddress(newOwner)
    {
        super.transferOwnership(newOwner);
    }

    function pause() external onlyOwner {
        _pause();
    }

    function unpause() external onlyOwner {
        _unpause();
    }

    function getBalance(address _user) external view returns (uint256) {
        return _balances[_user];
    }

    function getTotalDeposits() external view returns (uint256) {
        return _totalDeposits;
    }

    function isAdmin(address _addr) external view returns (bool) {
        return _admins[_addr];
    }

    receive() external payable {
        _balances[msg.sender] += msg.value;
        _totalDeposits += msg.value;
        emit Deposit(msg.sender, msg.value);
    }
}
