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

    // provider address -> control plane endpoint url
    mapping(address => string) public providers;

    uint256[49] private __gap_providers; // forge-lint: disable-line(mixed-case-variable)

    error MarketProviderAlreadyExists();
    error MarketProviderNotFound();
    error MarketProviderInvalidCp();

    event MarketProviderAdded(address indexed provider, string cp);
    event MarketProviderRemoved(address indexed provider);
    event MarketProviderUpdated(address indexed provider, string oldCp, string newCp);

    function _providerAdd(address _provider, string memory _cp) internal {
        require(bytes(providers[_provider]).length == 0, MarketProviderAlreadyExists());
        require(bytes(_cp).length != 0, MarketProviderInvalidCp());

        providers[_provider] = _cp;

        emit MarketProviderAdded(_provider, _cp);
    }

    function _providerRemove(address _provider) internal {
        require(bytes(providers[_provider]).length != 0, MarketProviderNotFound());

        delete providers[_provider];

        emit MarketProviderRemoved(_provider);
    }

    function _providerUpdate(address _provider, string memory _cp) internal {
        require(bytes(providers[_provider]).length != 0, MarketProviderNotFound());
        require(bytes(_cp).length != 0, MarketProviderInvalidCp());

        emit MarketProviderUpdated(_provider, providers[_provider], _cp);

        providers[_provider] = _cp;
    }

    function providerAdd(string memory _cp) external {
        return _providerAdd(_msgSender(), _cp);
    }

    function providerRemove() external {
        return _providerRemove(_msgSender());
    }

    function providerUpdate(string memory _cp) external {
        return _providerUpdate(_msgSender(), _cp);
    }

    /*---- Providers end ----*/

    /*---- Jobs start ----*/

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
    uint256 public noticePeriod;

    uint256[47] private __gap_jobs; // forge-lint: disable-line(mixed-case-variable)

    error MarketJobNotFound();
    error MarketOnlyJobOwner();
    error MarketInsufficientFundsToSettle();
    error MarketInvalidRate();
    error MarketInvalidAmount();
    error MarketJobInactive();
    error MarketInsufficientFundsToWithdraw();
    error MarketRateNotChanged();
    error MarketInsufficientFundsToSettleBeforeRevisingRate();
    error MarketInsufficientFunds();
    error MarketMetadataNotChanged();

    event MarketNoticePeriodUpdated(uint256 from, uint256 to);
    event MarketJobOpened(
        uint64 indexed jobId, uint256 timestamp, string metadata, address indexed owner, address indexed provider
    );
    event MarketJobSettled(uint64 indexed jobId, uint256 timestamp, uint256 amount, address indexed to);
    event MarketJobClosed(uint64 indexed jobId, uint256 timestamp);
    event MarketJobDeposited(uint64 indexed jobId, uint256 timestamp, uint256 amount, address indexed from);
    event MarketJobWithdrew(uint64 indexed jobId, uint256 timestamp, uint256 amount, address indexed to);
    event MarketJobRateRevised(uint64 indexed jobId, uint256 timestamp, uint256 newRate);
    event MarketJobMetadataUpdated(uint64 indexed jobId, uint256 timestamp, string metadata);

    modifier onlyExistingJob(uint64 _jobId) {
        _onlyExistingJob(_jobId);
        _;
    }

    function _onlyExistingJob(uint64 _jobId) internal view {
        require(jobs[_jobId].owner != address(0), MarketJobNotFound());
    }

    modifier onlyActiveJob(uint64 _jobId) {
        _onlyActiveJob(_jobId);
        _;
    }

    function _onlyActiveJob(uint64 _jobId) internal view {
        _onlyExistingJob(_jobId);
        require(
            (block.timestamp <= jobs[_jobId].lastSettled)
                || (_calcAmountUsed(jobs[_jobId].rate, block.timestamp - jobs[_jobId].lastSettled)
                        <= jobs[_jobId].balance),
            MarketJobInactive()
        );
    }

    modifier onlyJobOwner(uint64 _jobId) {
        _onlyJobOwner(_jobId);
        _;
    }

    function _onlyJobOwner(uint64 _jobId) internal view {
        require(jobs[_jobId].owner == _msgSender(), MarketOnlyJobOwner());
    }

    function _updateNoticePeriod(uint256 _noticePeriod) internal {
        emit MarketNoticePeriodUpdated(noticePeriod, _noticePeriod);
        noticePeriod = _noticePeriod;
    }

    function updateNoticePeriod(uint256 _noticePeriod) external onlyAdmin {
        _updateNoticePeriod(_noticePeriod);
    }

    function _emergencyWithdrawCredit(address _to, uint64[] calldata _jobIds) internal {
        for (uint256 i = 0; i < _jobIds.length; i++) {
            uint64 _jobId = _jobIds[i];
            _jobSettle(_jobId);
            uint256 _creditAmount = _withdrawAllCredit(_jobId, _to);
            jobs[_jobId].balance -= _creditAmount;
            emit MarketJobWithdrew(_jobId, block.timestamp, _creditAmount, _to);
        }
    }

    function emergencyWithdrawCredit(address _to, uint64[] calldata _jobIds) external onlyAdmin {
        _emergencyWithdrawCredit(_to, _jobIds);
    }

    function _jobOpen(string calldata _metadata, address _owner, address _provider, uint256 _rate, uint256 _balance)
        internal
    {
        uint64 _jobId = jobIndex;
        jobIndex = _jobId + 1;

        // create job with initial balance 0
        jobs[_jobId] = Job({
            metadata: _metadata,
            owner: _owner,
            provider: _provider,
            rate: 0,
            balance: 0,
            lastSettled: block.timestamp,
            maxRate: 0
        });
        emit MarketJobOpened(_jobId, block.timestamp, _metadata, _owner, _provider);

        // deposit initial balance
        _jobDeposit(_jobId, _balance, _owner);

        // set rate and pay shutdown delay cost upfront
        _jobReviseRate(_jobId, _rate);
    }

    function _jobSettle(uint64 _jobId) internal returns (bool) {
        uint256 _rate = jobs[_jobId].rate;
        uint256 _lastSettled = jobs[_jobId].lastSettled;
        uint256 _usageDuration = block.timestamp - _lastSettled;
        uint256 _amountUsed = _calcAmountUsed(_rate, _usageDuration);
        uint256 _settleAmount = _min(_amountUsed, jobs[_jobId].balance);
        address _provider = jobs[_jobId].provider;
        _settle(_jobId, _provider, _settleAmount);
        jobs[_jobId].balance -= _settleAmount;
        jobs[_jobId].lastSettled = block.timestamp;
        emit MarketJobSettled(_jobId, block.timestamp, _settleAmount, _provider);

        return _amountUsed == _settleAmount;
    }

    function _jobClose(uint64 _jobId) internal {
        _jobSettle(_jobId);

        // refund leftover balance
        uint256 _balance = jobs[_jobId].balance;
        if (_balance > 0) {
            _withdraw(_jobId, _balance, _msgSender(), _balance);
            emit MarketJobWithdrew(_jobId, block.timestamp, _balance, _msgSender());
        }

        delete jobs[_jobId];
        emit MarketJobClosed(_jobId, block.timestamp);
    }

    function _jobDeposit(uint64 _jobId, uint256 _amount, address _from) internal {
        _deposit(_jobId, _from, _amount);
        jobs[_jobId].balance += _amount;
        emit MarketJobDeposited(_jobId, block.timestamp, _amount, _from);
    }

    function _jobWithdraw(uint64 _jobId, uint256 _amount, address _to) internal {
        _jobSettle(_jobId);

        _withdraw(_jobId, jobs[_jobId].balance, _to, _amount);
        jobs[_jobId].balance -= _amount;
        emit MarketJobWithdrew(_jobId, block.timestamp, _amount, _to);
    }

    function _jobReviseRate(uint64 _jobId, uint256 _newRate) internal {
        _jobSettle(_jobId);

        // deduct shutdown delay cost
        // higher rate is used to calculate shutdown delay cost
        uint256 _oldRate = jobs[_jobId].rate;
        uint256 _higherRate = _max(_oldRate, _newRate);
        uint256 _prevHighestRate = jobs[_jobId].maxRate;
        if (_higherRate > _prevHighestRate) {
            jobs[_jobId].maxRate = _higherRate;
            uint256 _noticePeriodExtraCost = _calcAmountUsed((_higherRate - _prevHighestRate), noticePeriod);
            require(jobs[_jobId].balance > _noticePeriodExtraCost, MarketInsufficientFunds());
            address _provider = jobs[_jobId].provider;
            _settle(_jobId, _provider, _noticePeriodExtraCost);
            jobs[_jobId].balance -= _noticePeriodExtraCost;
            emit MarketJobSettled(_jobId, block.timestamp, _noticePeriodExtraCost, _provider);
        }

        // update rate
        jobs[_jobId].rate = _newRate;
        emit MarketJobRateRevised(_jobId, block.timestamp, _newRate);
    }

    function _jobMetadataUpdate(uint64 _jobId, string calldata _metadata) internal {
        jobs[_jobId].metadata = _metadata;
        emit MarketJobMetadataUpdated(_jobId, block.timestamp, _metadata);
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
        _jobSettle(_jobId);
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
    function jobDeposit(uint64 _jobId, uint256 _amount) external onlyActiveJob(_jobId) {
        _jobDeposit(_jobId, _amount, _msgSender());
    }

    /// @notice  Withdraws the specified amount from the job balance.
    ///          If the amount required to be withdrawn is greater than the job's balance, the remaining balance will be
    ///          transferred from the job to the caller as Credit tokens.
    /// @dev     Reverts if block.timestamp is before `lastSettled` of given jobId.
    /// @param   _jobId  The job to withdraw from.
    /// @param   _amount  The amount to withdraw.
    function jobWithdraw(uint64 _jobId, uint256 _amount) external onlyJobOwner(_jobId) onlyActiveJob(_jobId) {
        _jobWithdraw(_jobId, _amount, _msgSender());
    }

    /// @notice  Revises the rate of the job.
    ///          Deducts the shutdown delay cost from the job's balance before updating the rate.
    /// @dev     Reverts if the rate has not changed.
    /// @param   _jobId  The job to revise the rate of.
    /// @param   _newRate  The new rate of the job.
    function jobReviseRate(uint64 _jobId, uint256 _newRate) external onlyJobOwner(_jobId) onlyActiveJob(_jobId) {
        _jobReviseRate(_jobId, _newRate);
    }

    /// @notice  Updates the metadata of the job.
    /// @dev     Reverts if the metadata has not changed.
    /// @param   _jobId  The job to update the metadata of.
    /// @param   _metadata  The new metadata of the job.
    function jobMetadataUpdate(uint64 _jobId, string calldata _metadata) external onlyJobOwner(_jobId) onlyActiveJob(_jobId) {
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

    IERC20 public token;
    ICredit public creditToken;
    // job id -> credit balance
    mapping(uint64 => uint256) public creditBalances;

    uint256[47] private __gap_payments; // forge-lint: disable-line(mixed-case-variable)

    error MarketWithdrawalAmountExceedsJobBalance();
    error MarketCreditBalanceExceedsJobBalance();
    error MarketCreditTokenNotSet();

    event MarketTokenUpdated(address indexed oldToken, address indexed newToken);
    event MarketCreditTokenUpdated(address indexed oldCreditToken, address indexed newCreditToken);
    event MarketTokenDeposited(uint64 indexed jobId, uint256 timestamp, address indexed from, uint256 amount);
    event MarketCreditTokenDeposited(uint64 indexed jobId, uint256 timestamp, address indexed from, uint256 amount);
    event MarketTokenWithdrew(uint64 indexed jobId, uint256 timestamp, address indexed to, uint256 amount);
    event MarketCreditTokenWithdrew(uint64 indexed jobId, uint256 timestamp, address indexed to, uint256 amount);
    event MarketTokenSettled(uint64 indexed jobId, uint256 timestamp, address indexed to, uint256 amount);
    event MarketCreditTokenSettled(uint64 indexed jobId, uint256 timestamp, address indexed to, uint256 amount);

    function _updateToken(address _token) internal {
        address oldToken = address(token);
        token = IERC20(_token);
        emit MarketTokenUpdated(oldToken, _token);
    }

    function _updateCreditToken(address _creditToken) internal {
        address oldCreditToken = address(creditToken);
        creditToken = ICredit(_creditToken);
        emit MarketCreditTokenUpdated(oldCreditToken, _creditToken);
    }

    function updateToken(address _token) external onlyAdmin {
        _updateToken(_token);
    }

    function updateCreditToken(address _creditToken) external onlyAdmin {
        _updateCreditToken(_creditToken);
    }

    function _deposit(uint64 _jobId, address _from, uint256 _amount) internal {
        uint256 _creditAmount = 0;

        if (address(creditToken) != address(0)) {
            uint256 _creditBalance = _min(creditToken.balanceOf(_from), creditToken.allowance(_from, address(this)));
            if (_creditBalance > 0) {
                _creditAmount = _min(_amount, _creditBalance);
                creditToken.safeTransferFrom(_from, address(this), _creditAmount);
                creditBalances[_jobId] += _creditAmount;
                emit MarketCreditTokenDeposited(_jobId, block.timestamp, _from, _creditAmount);
            }
        }

        if (_amount > _creditAmount) {
            uint256 _tokenAmount = _amount - _creditAmount;
            token.safeTransferFrom(_from, address(this), _tokenAmount);
            emit MarketTokenDeposited(_jobId, block.timestamp, _from, _tokenAmount);
        }
    }

    function _settle(uint64 _jobId, address _to, uint256 _amount) internal {
        uint256 _creditAmount = 0;

        if (address(creditToken) != address(0)) {
            uint256 _creditBalance = creditBalances[_jobId];
            if (_creditBalance > 0) {
                _creditAmount = _min(_amount, _creditBalance);
                creditBalances[_jobId] -= _creditAmount;
                creditToken.redeemAndBurn(_to, _creditAmount);
                emit MarketCreditTokenSettled(_jobId, block.timestamp, _to, _creditAmount);
            }
        }

        if (_amount > _creditAmount) {
            uint256 _tokenAmount = _amount - _creditAmount;
            token.safeTransfer(_to, _tokenAmount);
            emit MarketTokenSettled(_jobId, block.timestamp, _to, _tokenAmount);
        }
    }

    function _withdraw(uint64 _jobId, uint256 _jobBalance, address _to, uint256 _amount) internal {
        uint256 _jobTokenBalance = _jobBalance - creditBalances[_jobId];
        uint256 _tokenAmount = _min(_jobTokenBalance, _amount);

        if (_tokenAmount > 0) {
            token.safeTransfer(_to, _tokenAmount);
            emit MarketTokenWithdrew(_jobId, block.timestamp, _to, _tokenAmount);
        }

        if (_amount > _tokenAmount) {
            uint256 _creditAmount = _amount - _tokenAmount;
            creditBalances[_jobId] -= _creditAmount;
            creditToken.safeTransfer(_to, _creditAmount);
            emit MarketCreditTokenWithdrew(_jobId, block.timestamp, _to, _creditAmount);
        }
    }

    function _withdrawAllCredit(uint64 _jobId, address _to) internal returns (uint256 _creditAmount) {
        _creditAmount = creditBalances[_jobId];
        creditBalances[_jobId] = 0;
        creditToken.safeTransfer(_to, _creditAmount);
        emit MarketCreditTokenWithdrew(_jobId, block.timestamp, _to, _creditAmount);
    }

    /*---- Payments end ----*/
}
