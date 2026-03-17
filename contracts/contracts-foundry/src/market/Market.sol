// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

/* Libraries */
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

/* Contracts */
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {ContextUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/ContextUpgradeable.sol";
import {ERC165Upgradeable} from "@openzeppelin/contracts-upgradeable/utils/introspection/ERC165Upgradeable.sol";
import {AccessControlUpgradeable} from "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";

/* Interfaces */
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {ICredit} from "../token/ICredit.sol";

contract Market is
    Initializable, // initializer
    ContextUpgradeable, // _msgSender, _msgData
    ERC165Upgradeable, // supportsInterface
    AccessControlUpgradeable, // RBAC
    UUPSUpgradeable // public upgrade
{
    using SafeERC20 for IERC20;
    using SafeERC20 for ICredit;

    // in case we add more contracts in the inheritance chain
    uint256[500] private __gap_0; // forge-lint: disable-line(mixed-case-variable)

    /// @custom:oz-upgrades-unsafe-allow constructor
    // disable all initializers and reinitializers
    // safeguard against takeover of the logic contract
    constructor() {
        _disableInitializers();
    }

    error MarketOnlyAdmin();

    modifier onlyAdmin() {
        _onlyAdmin();
        _;
    }

    function _onlyAdmin() internal view {
        require(hasRole(DEFAULT_ADMIN_ROLE, _msgSender()), MarketOnlyAdmin());
    }

    /*---- Overrides start ----*/

    function supportsInterface(bytes4 interfaceId)
        public
        view
        virtual
        override(ERC165Upgradeable, AccessControlUpgradeable)
        returns (bool)
    {
        return super.supportsInterface(interfaceId);
    }

    function _authorizeUpgrade(address) internal view override onlyAdmin {}

    /*---- Overrides end ----*/

    /*---- Initializer start ----*/

    uint256[50] private __gap_initializer; // forge-lint: disable-line(mixed-case-variable)

    function initialize(
        address _admin,
        uint64 _initialJobIndex,
        uint256 _noticePeriod,
        address _token,
        address _creditToken
    ) public initializer {
        __Context_init_unchained();
        __ERC165_init_unchained();
        __AccessControl_init_unchained();

        _grantRole(DEFAULT_ADMIN_ROLE, _admin);

        jobIndex = _initialJobIndex;
        _updateNoticePeriod(_noticePeriod);

        _updateToken(_token);
        _updateCreditToken(_creditToken);
    }

    /*---- Initializer end ----*/

    /*---- Providers start ----*/

    error MarketProviderAlreadyExists();
    error MarketProviderInvalid();
    error MarketProviderNotFound();

    // provider address -> control plane endpoint url
    mapping(address => string) public providers;

    uint256[49] private __gap_providers; // forge-lint: disable-line(mixed-case-variable)

    event ProviderAdded(address indexed provider, string cp);
    event ProviderRemoved(address indexed provider);
    event ProviderUpdatedWithCp(address indexed provider, string oldCp, string newCp);

    function _providerAdd(address _provider, string memory _cp) internal {
        require(bytes(providers[_provider]).length == 0, MarketProviderAlreadyExists());
        require(bytes(_cp).length != 0, MarketProviderInvalid());

        providers[_provider] = _cp;

        emit ProviderAdded(_provider, _cp);
    }

    function _providerRemove(address _provider) internal {
        require(bytes(providers[_provider]).length != 0, MarketProviderNotFound());

        delete providers[_provider];

        emit ProviderRemoved(_provider);
    }

    function _providerUpdateWithCp(address _provider, string memory _cp) internal {
        require(bytes(providers[_provider]).length != 0, MarketProviderNotFound());
        require(bytes(_cp).length != 0, MarketProviderInvalid());

        emit ProviderUpdatedWithCp(_provider, providers[_provider], _cp);

        providers[_provider] = _cp;
    }

    function providerAdd(string memory _cp) external {
        return _providerAdd(_msgSender(), _cp);
    }

    function providerRemove() external {
        return _providerRemove(_msgSender());
    }

    function providerUpdateWithCp(string memory _cp) external {
        return _providerUpdateWithCp(_msgSender(), _cp);
    }

    /*---- Providers end ----*/

    /*---- Jobs start ----*/

    error MarketJobNotFound();
    error MarketOnlyJobOwner();
    error MarketOnlyEmergencyWithdrawRole();
    error MarketInsufficientFundsToSettle();
    error MarketInvalidRate();
    error MarketInvalidAmount();
    error MarketInsufficientFundsToDeposit();
    error MarketInsufficientFundsToWithdraw();
    error MarketRateNotChanged();
    error MarketInsufficientFundsToSettleBeforeRevisingRate();
    error MarketInsufficientFundsToReviseRate();
    error MarketMetadataNotChanged();

    bytes32 public constant EMERGENCY_WITHDRAW_ROLE = keccak256("EMERGENCY_WITHDRAW_ROLE");
    uint256 public constant EXTRA_DECIMALS = 12;

    struct Job {
        string metadata;
        address owner;
        address provider;
        uint256 rate;
        uint256 balance;
        uint256 lastSettled; // payment has been settled up to this timestamp
        uint256 maxRate; // max rate for the job
    }
    mapping(uint64 => Job) public jobs;
    uint64 public jobIndex;
    uint256 noticePeriod;

    uint256[46] private __gap_jobs; // forge-lint: disable-line(mixed-case-variable)

    event TokenUpdated(address indexed oldToken, address indexed newToken);
    event CreditTokenUpdated(address indexed oldCreditToken, address indexed newCreditToken);
    event NoticePeriodUpdated(uint256 noticePeriod);

    event JobOpened(
        uint64 indexed jobId, string metadata, address indexed owner, address indexed provider, uint256 timestamp
    );
    event JobSettled(uint64 indexed jobId, uint256 lastSettled);
    event JobClosed(uint64 indexed jobId, uint256 timestamp);
    event JobDeposited(uint64 indexed jobId, address indexed token, address indexed from, uint256 amount);
    event JobWithdrawn(uint64 indexed jobId, address indexed token, address indexed to, uint256 amount);
    event JobSettlementWithdrawn(uint64 indexed jobId, address indexed token, address indexed provider, uint256 amount);
    event JobRateRevised(uint64 indexed jobId, uint256 newRate);
    event JobMetadataUpdated(uint64 indexed jobId, string metadata);

    modifier onlyExistingJob(uint64 _jobId) {
        _onlyExistingJob(_jobId);
        _;
    }

    function _onlyExistingJob(uint64 _jobId) internal view {
        require(jobs[_jobId].owner != address(0), MarketJobNotFound());
    }

    modifier onlyJobOwner(uint64 _jobId) {
        _onlyJobOwner(_jobId);
        _;
    }

    function _onlyJobOwner(uint64 _jobId) internal view {
        require(jobs[_jobId].owner == _msgSender(), MarketOnlyJobOwner());
    }

    function _updateToken(address _token) internal {
        address oldToken = address(realToken);
        realToken = IERC20(_token);
        emit TokenUpdated(oldToken, _token);
    }

    function _updateNoticePeriod(uint256 _noticePeriod) internal {
        noticePeriod = _noticePeriod;
        emit NoticePeriodUpdated(_noticePeriod);
    }

    function _updateCreditToken(address _creditToken) internal {
        address oldCreditToken = address(creditToken);
        creditToken = ICredit(_creditToken);
        emit CreditTokenUpdated(oldCreditToken, _creditToken);
    }

    function updateToken(address _token) external onlyAdmin {
        _updateToken(_token);
    }

    function updateNoticePeriod(uint256 _noticePeriod) external onlyAdmin {
        _updateNoticePeriod(_noticePeriod);
    }

    function updateCreditToken(address _creditToken) external onlyAdmin {
        _updateCreditToken(_creditToken);
    }

    function _emergencyWithdrawCredit(address _to, uint64[] calldata _jobIds) internal {
        require(hasRole(EMERGENCY_WITHDRAW_ROLE, _to), MarketOnlyEmergencyWithdrawRole());

        for (uint256 i = 0; i < _jobIds.length; i++) {
            uint64 jobId = _jobIds[i];
            _jobSettle(jobId, jobs[jobId].rate);
            uint256 creditBalance = jobCreditBalance[jobId];
            if (creditBalance > 0) {
                jobs[jobId].balance -= creditBalance;
                // set job credit balance to 0
                jobCreditBalance[jobId] = 0;
                creditToken.safeTransfer(_to, creditBalance);
                emit JobWithdrawn(jobId, address(creditToken), _to, creditBalance);
            }
        }
    }

    function emergencyWithdrawCredit(address _to, uint64[] calldata _jobIds) external onlyAdmin {
        _emergencyWithdrawCredit(_to, _jobIds);
    }

    function _jobOpen(string calldata _metadata, address _owner, address _provider, uint256 _rate, uint256 _balance)
        internal
    {
        uint64 jobId = jobIndex;
        jobIndex = jobId + 1;

        // create job with initial balance 0
        jobs[jobId] = Job({
            metadata: _metadata,
            owner: _owner,
            provider: _provider,
            rate: 0,
            balance: 0,
            lastSettled: block.timestamp,
            maxRate: 0
        });
        emit JobOpened(jobId, _metadata, _owner, _provider, block.timestamp);

        // deposit initial balance
        _deposit(jobId, _msgSender(), _balance);

        // set rate and pay shutdown delay cost upfront
        _jobReviseRate(jobId, _rate);
    }

    function _jobSettle(uint64 _jobId, uint256 _rate) internal returns (bool isBalanceEnough) {
        uint256 lastSettled = jobs[_jobId].lastSettled;

        if (block.timestamp <= lastSettled) {
            return true;
        }
        require(jobs[_jobId].balance > 0, MarketInsufficientFundsToSettle());
        require(jobs[_jobId].rate > 0, MarketInvalidRate());

        uint256 usageDuration = block.timestamp - lastSettled;
        uint256 amountUsed = _calcAmountUsed(_rate, usageDuration);
        uint256 settleAmount = _min(amountUsed, jobs[_jobId].balance);
        _settle(_jobId, settleAmount);
        jobs[_jobId].lastSettled = block.timestamp;
        emit JobSettled(_jobId, block.timestamp);

        isBalanceEnough = amountUsed <= settleAmount;
    }

    function _jobClose(uint64 _jobId) internal {
        // deduct shutdown delay cost
        _jobSettle(_jobId, jobs[_jobId].rate);

        // refund leftover balance
        uint256 _balance = jobs[_jobId].balance;
        if (_balance > 0) {
            _withdraw(_jobId, _msgSender(), _balance);
        }

        delete jobs[_jobId];
        emit JobClosed(_jobId, block.timestamp);
    }

    function _jobDeposit(uint64 _jobId, uint256 _amount) internal {
        require(_amount > 0, MarketInvalidAmount());
        require(_jobSettle(_jobId, jobs[_jobId].rate), MarketInsufficientFundsToDeposit());

        _deposit(_jobId, _msgSender(), _amount);
    }

    function _jobWithdraw(uint64 _jobId, uint256 _amount) internal {
        require(_amount > 0, MarketInvalidAmount());
        require(_jobSettle(_jobId, jobs[_jobId].rate), MarketInsufficientFundsToWithdraw());

        // withdraw
        _withdraw(_jobId, _msgSender(), _amount);
    }

    function _jobReviseRate(uint64 _jobId, uint256 _newRate) internal {
        require(_newRate > 0, MarketInvalidRate());
        require(jobs[_jobId].rate != _newRate, MarketRateNotChanged());

        uint256 lastSettled = jobs[_jobId].lastSettled;
        if (block.timestamp > lastSettled) {
            require(_jobSettle(_jobId, jobs[_jobId].rate), MarketInsufficientFundsToSettleBeforeRevisingRate());
        }

        // update rate and lastSettled
        uint256 oldRate = jobs[_jobId].rate;
        jobs[_jobId].rate = _newRate;
        emit JobRateRevised(_jobId, _newRate);

        // deduct shutdown delay cost
        // higher rate is used to calculate shutdown delay cost
        uint256 higherRate = _max(oldRate, _newRate);
        uint256 prevHighestRate = jobs[_jobId].maxRate;
        if (higherRate > prevHighestRate) {
            jobs[_jobId].maxRate = higherRate;
            uint256 noticePeriodExtraCost = _calcAmountUsed((higherRate - prevHighestRate), noticePeriod);
            require(jobs[_jobId].balance > noticePeriodExtraCost, MarketInsufficientFundsToReviseRate());
            _settle(_jobId, noticePeriodExtraCost);
        }
    }

    function _jobMetadataUpdate(uint64 _jobId, string calldata _metadata) internal {
        string memory oldMetadata = jobs[_jobId].metadata;
        require(
            keccak256(abi.encodePacked(oldMetadata)) != keccak256(abi.encodePacked(_metadata)),
            MarketMetadataNotChanged()
        );
        jobs[_jobId].metadata = _metadata;
        emit JobMetadataUpdated(_jobId, _metadata);
    }

    /// @notice  Opens a new job.
    ///          To ensure the provider is paid for the shutdown window, if the deposit amount is exactly equal to
    ///          the noticePeriodCost, the provider is incentivized to shut down the job immediately after opening.
    ///          Therefore, it should be noted that `(deposit amount) - noticePeriodCost` is the actual amount to be
    ///          used for running the job.
    /// @dev     `noticePeriodCost` is paid upfront.
    ///          min(_balance, creditAllowance, creditBalance) amount of Credit tokens will be transferred from the caller to the job.
    /// @param   _metadata  The metadata of the job.
    /// @param   _provider  The provider of the job.
    /// @param   _rate      The rate of the job.
    /// @param   _balance   Amount of tokens to deposit into the job.
    function jobOpen(string calldata _metadata, address _provider, uint256 _rate, uint256 _balance) external {
        _jobOpen(_metadata, _msgSender(), _provider, _rate, _balance);
    }

    /// @notice  Settles the job and sends the amount settled to the job's provider.
    ///          If the job has Credit balance, the credit balance will be deducted first.
    /// @dev     Reverts if block.timestamp is before `lastSettled` of given jobId.
    ///          If settled with Credit tokens the Credit tokens will be burned and redeemed to USDC when transfering
    ///          to the job's provider.
    /// @param   _jobId  The job to settle.
    function jobSettle(uint64 _jobId) external onlyExistingJob(_jobId) {
        _jobSettle(_jobId, jobs[_jobId].rate);
    }

    /// @notice  Closes the job and sends the remaining balance to the job's owner.
    ///          The shutdown delay cost is deducted from the job's balance before refunding the remaining balance.
    /// @dev     Settles the job before closing it.
    /// @param   _jobId  The job to close.
    function jobClose(uint64 _jobId) external onlyJobOwner(_jobId) {
        _jobClose(_jobId);
    }

    /// @notice  Deposits the specified amount into the job balance.
    ///          min(_amount, creditAllowance, creditBalance) amount of Credit tokens will be transferred from the caller to the job.
    /// @param   _jobId  The job to deposit to.
    /// @param   _amount  The amount to deposit.
    function jobDeposit(uint64 _jobId, uint256 _amount) external onlyExistingJob(_jobId) {
        _jobDeposit(_jobId, _amount);
    }

    /// @notice  Withdraws the specified amount from the job balance.
    ///          If the amount required to be withdrawn is greater than the job's balance, the remaining balance will be
    ///          transferred from the job to the caller as Credit tokens.
    /// @dev     Reverts if block.timestamp is before `lastSettled` of given jobId.
    /// @param   _jobId  The job to withdraw from.
    /// @param   _amount  The amount to withdraw.
    function jobWithdraw(uint64 _jobId, uint256 _amount) external onlyJobOwner(_jobId) {
        _jobWithdraw(_jobId, _amount);
    }

    /// @notice  Revises the rate of the job.
    ///          Deducts the shutdown delay cost from the job's balance before updating the rate.
    /// @dev     Reverts if the rate has not changed.
    /// @param   _jobId  The job to revise the rate of.
    /// @param   _newRate  The new rate of the job.
    function jobReviseRate(uint64 _jobId, uint256 _newRate) external onlyJobOwner(_jobId) {
        _jobReviseRate(_jobId, _newRate);
    }

    /// @notice  Updates the metadata of the job.
    /// @dev     Reverts if the metadata has not changed.
    /// @param   _jobId  The job to update the metadata of.
    /// @param   _metadata  The new metadata of the job.
    function jobMetadataUpdate(uint64 _jobId, string calldata _metadata) external onlyJobOwner(_jobId) {
        _jobMetadataUpdate(_jobId, _metadata);
    }

    function _calcAmountUsed(uint256 _rate, uint256 _usageDuration) internal pure returns (uint256) {
        return (_rate * _usageDuration + 10 ** EXTRA_DECIMALS - 1) / 10 ** EXTRA_DECIMALS;
    }

    function _max(uint256 _a, uint256 _b) internal pure returns (uint256) {
        return _a > _b ? _a : _b;
    }

    function _min(uint256 _a, uint256 _b) internal pure returns (uint256) {
        return _a < _b ? _a : _b;
    }

    /*---- Jobs end ----*/

    /*---- Payments start ----*/

    error MarketWithdrawalAmountExceedsJobBalance();
    error MarketCreditBalanceExceedsJobBalance();
    error MarketCreditTokenNotSet();

    IERC20 public realToken;
    ICredit public creditToken;
    mapping(uint64 => uint256) public jobCreditBalance;

    uint256[50] private __gap_payments; // forge-lint: disable-line(mixed-case-variable)

    /// @notice  Deposits the specified amount into the job balance.
    /// @param   _jobId  The job to deposit to.
    /// @param   _from  The address to deposit from.
    /// @param   _amount  The amount to deposit.
    function _deposit(uint64 _jobId, address _from, uint256 _amount) internal {
        uint256 tokenAmount = _amount;
        uint256 creditAmount = 0;

        if (address(creditToken) != address(0)) {
            // amount to transfer from credit token
            uint256 creditBalance = _min(creditToken.balanceOf(_from), creditToken.allowance(_from, address(this)));

            if (creditBalance > 0) {
                (creditAmount, tokenAmount) = _calculateTokenSplit(_amount, creditBalance);
                creditToken.safeTransferFrom(_from, address(this), creditAmount);
                jobCreditBalance[_jobId] += creditAmount;
                emit JobDeposited(_jobId, address(creditToken), _from, creditAmount);
            }
        }

        if (tokenAmount > 0) {
            realToken.safeTransferFrom(_from, address(this), tokenAmount);
            emit JobDeposited(_jobId, address(realToken), _from, tokenAmount);
        }

        jobs[_jobId].balance += _amount;
    }

    function _settle(uint64 _jobId, uint256 _amount) internal {
        address provider = jobs[_jobId].provider;

        jobs[_jobId].balance -= _amount;

        uint256 tokenAmount = _amount;
        uint256 creditAmount = 0;

        if (address(creditToken) != address(0)) {
            uint256 creditBalance = jobCreditBalance[_jobId];

            if (creditBalance > 0) {
                (creditAmount, tokenAmount) = _calculateTokenSplit(_amount, creditBalance);
                jobCreditBalance[_jobId] -= creditAmount;
                ICredit(address(creditToken)).redeemAndBurn(provider, creditAmount);
                emit JobSettlementWithdrawn(_jobId, address(creditToken), provider, creditAmount);
            }
        }

        if (tokenAmount > 0) {
            realToken.safeTransfer(provider, tokenAmount);
            emit JobSettlementWithdrawn(_jobId, address(realToken), provider, tokenAmount);
        }
    }

    /// @notice  Calculates how much of each token type to use
    /// @param   _totalAmount Total amount to process
    /// @param   _creditBalance Available credit token amount
    /// @return   creditAmount Amount to handle with credit tokens
    /// @return  tokenAmount Amount to handle with payment tokens
    function _calculateTokenSplit(uint256 _totalAmount, uint256 _creditBalance)
        internal
        pure
        returns (uint256 creditAmount, uint256 tokenAmount)
    {
        if (_totalAmount > _creditBalance) {
            creditAmount = _creditBalance;
            tokenAmount = _totalAmount - _creditBalance;
        } else {
            creditAmount = _totalAmount;
            tokenAmount = 0;
        }
        return (creditAmount, tokenAmount);
    }

    /// @notice  Withdraws the specified amount from the job balance.
    /// @param   _jobId  The job to withdraw from.
    /// @param   _to  The address to withdraw to.
    /// @param   _amount  The amount to withdraw.
    function _withdraw(uint64 _jobId, address _to, uint256 _amount) internal {
        uint256 jobBalance = jobs[_jobId].balance;
        require(jobBalance >= _amount, MarketWithdrawalAmountExceedsJobBalance());

        uint256 withdrawAmount = _amount;

        // shouldn't be possible
        uint256 jobCreditBalance_ = jobCreditBalance[_jobId];
        require(jobBalance >= jobCreditBalance_, MarketCreditBalanceExceedsJobBalance());
        uint256 jobTokenBalance = jobBalance - jobCreditBalance_;
        jobs[_jobId].balance -= withdrawAmount;

        uint256 tokenAmountToTransfer;
        if (jobTokenBalance < withdrawAmount) {
            tokenAmountToTransfer = jobTokenBalance;
            withdrawAmount -= jobTokenBalance;
        } else {
            tokenAmountToTransfer = withdrawAmount;
            withdrawAmount = 0;
        }

        if (tokenAmountToTransfer > 0) {
            realToken.safeTransfer(_to, tokenAmountToTransfer);
            emit JobWithdrawn(_jobId, address(realToken), _to, tokenAmountToTransfer);
        }

        if (withdrawAmount > 0) {
            require(address(creditToken) != address(0), MarketCreditTokenNotSet());
            jobCreditBalance[_jobId] -= withdrawAmount;
            creditToken.safeTransfer(_to, withdrawAmount);
            emit JobWithdrawn(_jobId, address(creditToken), _to, withdrawAmount);
        }
    }

    /*---- Payments end ----*/
}
