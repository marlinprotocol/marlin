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

/// @title Market Contract
/// @notice Manages jobs, providers, and payments
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

    /// @notice Thrown when caller is not admin
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

    /// @notice Initializes the Market contract
    /// @param _admin Address of the contract admin
    /// @param _initialJobIndex Initial job index
    /// @param _noticePeriod Notice period for rate changes
    /// @param _token Address of the ERC20 token
    /// @param _creditToken Address of the Credit token
    function initialize(
        address _admin,
        uint64 _initialJobIndex,
        uint64 _noticePeriod,
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

    /// @custom:storage-location ERC7201:marlin.storage.Market.providers
    struct ProvidersStorage {
        /// @notice Mapping of provider address to control plane endpoint url
        mapping(address => string) providers;
    }

    // keccak256(abi.encode(uint256(keccak256("marlin.storage.Market.providers")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant PROVIDERS_STORAGE_LOCATION =
        0x84127d05d3686c1ef79b9015b6c3f0823997e8a0ac6ae09b6d4a6930c2de9200;

    function _getProvidersStorage() private pure returns (ProvidersStorage storage $) {
        assembly {
            $.slot := PROVIDERS_STORAGE_LOCATION
        }
    }

    /// @notice Thrown when provider already exists
    error MarketProviderAlreadyExists();
    /// @notice Thrown when provider does not exist
    error MarketProviderNotFound();
    /// @notice Thrown when provider control plane endpoint is invalid
    error MarketProviderInvalidCp();

    /// @notice Emitted when a provider is added
    event MarketProviderAdded(address indexed provider, string cp);
    /// @notice Emitted when a provider is removed
    event MarketProviderRemoved(address indexed provider);
    /// @notice Emitted when a provider is updated
    event MarketProviderUpdated(address indexed provider, string oldCp, string newCp);

    function providers(address _provider) public view returns (string memory) {
        ProvidersStorage storage $ = _getProvidersStorage();

        return $.providers[_provider];
    }

    function _providerAdd(address _provider, string memory _cp) internal {
        ProvidersStorage storage $ = _getProvidersStorage();

        require(bytes($.providers[_provider]).length == 0, MarketProviderAlreadyExists());
        require(bytes(_cp).length != 0, MarketProviderInvalidCp());

        $.providers[_provider] = _cp;

        emit MarketProviderAdded(_provider, _cp);
    }

    function _providerRemove(address _provider) internal {
        ProvidersStorage storage $ = _getProvidersStorage();

        require(bytes($.providers[_provider]).length != 0, MarketProviderNotFound());

        delete $.providers[_provider];

        emit MarketProviderRemoved(_provider);
    }

    function _providerUpdate(address _provider, string memory _cp) internal {
        ProvidersStorage storage $ = _getProvidersStorage();

        require(bytes($.providers[_provider]).length != 0, MarketProviderNotFound());
        require(bytes(_cp).length != 0, MarketProviderInvalidCp());

        emit MarketProviderUpdated(_provider, $.providers[_provider], _cp);

        $.providers[_provider] = _cp;
    }

    /// @notice Adds a provider
    /// @param _cp Control plane endpoint url
    function providerAdd(string memory _cp) external {
        return _providerAdd(_msgSender(), _cp);
    }

    /// @notice Removes a provider
    function providerRemove() external {
        return _providerRemove(_msgSender());
    }

    /// @notice Updates a provider
    /// @param _cp New control plane endpoint url
    function providerUpdate(string memory _cp) external {
        return _providerUpdate(_msgSender(), _cp);
    }

    /*---- Providers end ----*/

    /*---- Jobs start ----*/

    uint256 public constant EXTRA_DECIMALS = 6;

    /// @notice Struct representing a Job
    struct Job {
        string metadata;
        address owner;
        address provider;
        uint64 rate;
        uint64 balance;
        uint64 lastSettled;
        uint64 maxRate;
    }
    /// @notice Mapping of job ID to Job struct
    mapping(uint64 => Job) public jobs;
    /// @notice Current job ID index
    uint64 public jobIndex;
    /// @notice Notice period for rate changes
    uint64 public noticePeriod;

    uint256[48] private __gap_jobs; // forge-lint: disable-line(mixed-case-variable)

    /// @notice Thrown when job does not exist
    error MarketJobNotFound();
    /// @notice Thrown when caller is not job owner
    error MarketJobOnlyOwner();
    /// @notice Thrown when job is inactive
    error MarketJobInactive();
    /// @notice Thrown when value is out of range
    error MarketOutOfRange();

    /// @notice Emitted when notice period is updated
    event MarketNoticePeriodUpdated(uint64 from, uint64 to);
    /// @notice Emitted when a job is opened
    event MarketJobOpened(
        uint64 indexed jobId, uint64 timestamp, string metadata, address indexed owner, address indexed provider
    );
    /// @notice Emitted when a job is settled
    event MarketJobSettled(uint64 indexed jobId, uint64 timestamp, uint64 amount, address indexed to);
    /// @notice Emitted when a job is closed
    event MarketJobClosed(uint64 indexed jobId, uint64 timestamp);
    /// @notice Emitted when a job is deposited to
    event MarketJobDeposited(uint64 indexed jobId, uint64 timestamp, uint64 amount, address indexed from);
    /// @notice Emitted when a job is withdrawn from
    event MarketJobWithdrew(uint64 indexed jobId, uint64 timestamp, uint64 amount, address indexed to);
    /// @notice Emitted when a job's rate is revised
    event MarketJobRateRevised(uint64 indexed jobId, uint64 timestamp, uint64 newRate);
    /// @notice Emitted when a job's metadata is updated
    event MarketJobMetadataUpdated(uint64 indexed jobId, uint64 timestamp, string metadata);

    function _now() internal view returns (uint64) {
        return uint64(block.timestamp);
    }

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
            (_now() <= jobs[_jobId].lastSettled)
                || (_calcAmountUsed(jobs[_jobId].rate, _now() - jobs[_jobId].lastSettled) <= jobs[_jobId].balance),
            MarketJobInactive()
        );
    }

    modifier onlyJobOwner(uint64 _jobId) {
        _onlyJobOwner(_jobId);
        _;
    }

    function _onlyJobOwner(uint64 _jobId) internal view {
        require(jobs[_jobId].owner == _msgSender(), MarketJobOnlyOwner());
    }

    function _updateNoticePeriod(uint64 _noticePeriod) internal {
        emit MarketNoticePeriodUpdated(noticePeriod, _noticePeriod);
        noticePeriod = _noticePeriod;
    }

    /// @notice Updates the notice period
    /// @param _noticePeriod New notice period
    function updateNoticePeriod(uint64 _noticePeriod) external onlyAdmin {
        _updateNoticePeriod(_noticePeriod);
    }

    function _emergencyWithdrawCredit(address _to, uint64[] calldata _jobIds) internal {
        for (uint256 i = 0; i < _jobIds.length; i++) {
            uint64 _jobId = _jobIds[i];
            _jobSettle(_jobId);
            uint64 _creditAmount = _withdrawAllCredit(_jobId, _to);
            jobs[_jobId].balance -= _creditAmount;
            emit MarketJobWithdrew(_jobId, _now(), _creditAmount, _to);
        }
    }

    /// @notice Emergency withdraws credit from specified jobs
    /// @param _to Address to send withdrawn credits to
    /// @param _jobIds Array of job IDs to withdraw credits from
    function emergencyWithdrawCredit(address _to, uint64[] calldata _jobIds) external onlyAdmin {
        _emergencyWithdrawCredit(_to, _jobIds);
    }

    function _jobOpen(string calldata _metadata, address _owner, address _provider, uint64 _rate, uint64 _balance)
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
            lastSettled: _now(),
            maxRate: 0
        });
        emit MarketJobOpened(_jobId, _now(), _metadata, _owner, _provider);

        // deposit initial balance
        _jobDeposit(_jobId, _balance, _owner);

        // set rate and pay shutdown delay cost upfront
        _jobReviseRate(_jobId, _rate);
    }

    function _jobSettle(uint64 _jobId) internal returns (bool) {
        uint64 _rate = jobs[_jobId].rate;
        uint64 _lastSettled = jobs[_jobId].lastSettled;
        uint64 _usageDuration = _now() - _lastSettled;
        uint64 _amountUsed = _calcAmountUsed(_rate, _usageDuration);
        uint64 _settleAmount = _min(_amountUsed, jobs[_jobId].balance);
        address _provider = jobs[_jobId].provider;
        _settle(_jobId, _provider, _settleAmount);
        jobs[_jobId].balance -= _settleAmount;
        jobs[_jobId].lastSettled = _now();
        emit MarketJobSettled(_jobId, _now(), _settleAmount, _provider);

        return _amountUsed == _settleAmount;
    }

    function _jobClose(uint64 _jobId) internal {
        _jobSettle(_jobId);

        // refund leftover balance
        uint64 _balance = jobs[_jobId].balance;
        if (_balance > 0) {
            _withdraw(_jobId, _balance, _msgSender(), _balance);
            emit MarketJobWithdrew(_jobId, _now(), _balance, _msgSender());
        }

        delete jobs[_jobId];
        emit MarketJobClosed(_jobId, _now());
    }

    function _jobDeposit(uint64 _jobId, uint64 _amount, address _from) internal {
        _deposit(_jobId, _from, _amount);
        jobs[_jobId].balance += _amount;
        emit MarketJobDeposited(_jobId, _now(), _amount, _from);
    }

    function _jobWithdraw(uint64 _jobId, uint64 _amount, address _to) internal {
        _jobSettle(_jobId);

        _withdraw(_jobId, jobs[_jobId].balance, _to, _amount);
        jobs[_jobId].balance -= _amount;
        emit MarketJobWithdrew(_jobId, _now(), _amount, _to);
    }

    function _jobReviseRate(uint64 _jobId, uint64 _newRate) internal {
        _jobSettle(_jobId);

        // deduct shutdown delay cost
        // higher rate is used to calculate shutdown delay cost
        uint64 _oldRate = jobs[_jobId].rate;
        uint64 _higherRate = _max(_oldRate, _newRate);
        uint64 _prevHighestRate = jobs[_jobId].maxRate;
        if (_higherRate > _prevHighestRate) {
            jobs[_jobId].maxRate = _higherRate;
            uint64 _noticePeriodExtraCost = _calcAmountUsed((_higherRate - _prevHighestRate), noticePeriod);
            address _provider = jobs[_jobId].provider;
            _settle(_jobId, _provider, _noticePeriodExtraCost);
            jobs[_jobId].balance -= _noticePeriodExtraCost;
            emit MarketJobSettled(_jobId, _now(), _noticePeriodExtraCost, _provider);
        }

        // update rate
        jobs[_jobId].rate = _newRate;
        emit MarketJobRateRevised(_jobId, _now(), _newRate);
    }

    function _jobMetadataUpdate(uint64 _jobId, string calldata _metadata) internal {
        jobs[_jobId].metadata = _metadata;
        emit MarketJobMetadataUpdated(_jobId, _now(), _metadata);
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
    function jobOpen(string calldata _metadata, address _provider, uint64 _rate, uint64 _balance) external {
        _jobOpen(_metadata, _msgSender(), _provider, _rate, _balance);
    }

    /// @notice  Settles the job and sends the amount settled to the job's provider.
    ///          If the job has Credit balance, the credit balance will be deducted first.
    /// @dev     Reverts if _now() is before `lastSettled` of given jobId.
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
    function jobDeposit(uint64 _jobId, uint64 _amount) external onlyActiveJob(_jobId) {
        _jobDeposit(_jobId, _amount, _msgSender());
    }

    /// @notice  Withdraws the specified amount from the job balance.
    ///          If the amount required to be withdrawn is greater than the job's balance, the remaining balance will be
    ///          transferred from the job to the caller as Credit tokens.
    /// @dev     Reverts if _now() is before `lastSettled` of given jobId.
    /// @param   _jobId  The job to withdraw from.
    /// @param   _amount  The amount to withdraw.
    function jobWithdraw(uint64 _jobId, uint64 _amount) external onlyJobOwner(_jobId) onlyActiveJob(_jobId) {
        _jobWithdraw(_jobId, _amount, _msgSender());
    }

    /// @notice  Revises the rate of the job.
    ///          Deducts the shutdown delay cost from the job's balance before updating the rate.
    /// @dev     Reverts if the rate has not changed.
    /// @param   _jobId  The job to revise the rate of.
    /// @param   _newRate  The new rate of the job.
    function jobReviseRate(uint64 _jobId, uint64 _newRate) external onlyJobOwner(_jobId) onlyActiveJob(_jobId) {
        _jobReviseRate(_jobId, _newRate);
    }

    /// @notice  Updates the metadata of the job.
    /// @dev     Reverts if the metadata has not changed.
    /// @param   _jobId  The job to update the metadata of.
    /// @param   _metadata  The new metadata of the job.
    function jobMetadataUpdate(uint64 _jobId, string calldata _metadata)
        external
        onlyJobOwner(_jobId)
        onlyActiveJob(_jobId)
    {
        _jobMetadataUpdate(_jobId, _metadata);
    }

    function _calcAmountUsed(uint64 _rate, uint64 _usageDuration) internal pure returns (uint64) {
        return _safe64((uint256(_rate) * uint256(_usageDuration) + 10 ** EXTRA_DECIMALS - 1) / 10 ** EXTRA_DECIMALS);
    }

    function _max(uint64 _a, uint64 _b) internal pure returns (uint64) {
        return _a > _b ? _a : _b;
    }

    function _min(uint64 _a, uint64 _b) internal pure returns (uint64) {
        return _a < _b ? _a : _b;
    }

    function _safe64(uint256 _x) internal pure returns (uint64) {
        require(_x < type(uint64).max, MarketOutOfRange());
        return uint64(_x);
    }

    /*---- Jobs end ----*/

    /*---- Payments start ----*/

    /// @notice ERC20 token used for payments
    IERC20 public token;
    /// @notice Credit token used for payments
    ICredit public creditToken;
    /// @notice Mapping of job ID to credit balance
    mapping(uint64 => uint64) public creditBalances;

    uint256[47] private __gap_payments; // forge-lint: disable-line(mixed-case-variable)

    /// @notice Emitted when the ERC20 token is updated
    event MarketTokenUpdated(address indexed oldToken, address indexed newToken);
    /// @notice Emitted when the Credit token is updated
    event MarketCreditTokenUpdated(address indexed oldCreditToken, address indexed newCreditToken);
    /// @notice Emitted when token is deposited
    event MarketTokenDeposited(uint64 indexed jobId, uint64 timestamp, address indexed from, uint64 amount);
    /// @notice Emitted when credit token is deposited
    event MarketCreditTokenDeposited(uint64 indexed jobId, uint64 timestamp, address indexed from, uint64 amount);
    /// @notice Emitted when token is withdrawn
    event MarketTokenWithdrew(uint64 indexed jobId, uint64 timestamp, address indexed to, uint64 amount);
    /// @notice Emitted when credit token is withdrawn
    event MarketCreditTokenWithdrew(uint64 indexed jobId, uint64 timestamp, address indexed to, uint64 amount);
    /// @notice Emitted when token is settled
    event MarketTokenSettled(uint64 indexed jobId, uint64 timestamp, address indexed to, uint64 amount);
    /// @notice Emitted when credit token is settled
    event MarketCreditTokenSettled(uint64 indexed jobId, uint64 timestamp, address indexed to, uint64 amount);

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

    /// @notice Updates the token
    /// @param _token Address of the new ERC20 token
    function updateToken(address _token) external onlyAdmin {
        _updateToken(_token);
    }

    /// @notice Updates the credit token
    /// @param _creditToken Address of the new Credit token
    function updateCreditToken(address _creditToken) external onlyAdmin {
        _updateCreditToken(_creditToken);
    }

    function _deposit(uint64 _jobId, address _from, uint64 _amount) internal {
        uint64 _creditAmount = 0;

        if (address(creditToken) != address(0)) {
            uint64 _creditBalance =
                _min(_safe64(creditToken.balanceOf(_from)), _safe64(creditToken.allowance(_from, address(this))));
            if (_creditBalance > 0) {
                _creditAmount = _min(_amount, _creditBalance);
                creditToken.safeTransferFrom(_from, address(this), _creditAmount);
                creditBalances[_jobId] += _creditAmount;
                emit MarketCreditTokenDeposited(_jobId, _now(), _from, _creditAmount);
            }
        }

        if (_amount > _creditAmount) {
            uint64 _tokenAmount = _amount - _creditAmount;
            token.safeTransferFrom(_from, address(this), _tokenAmount);
            emit MarketTokenDeposited(_jobId, _now(), _from, _tokenAmount);
        }
    }

    function _settle(uint64 _jobId, address _to, uint64 _amount) internal {
        uint64 _creditAmount = 0;

        if (address(creditToken) != address(0)) {
            uint64 _creditBalance = creditBalances[_jobId];
            if (_creditBalance > 0) {
                _creditAmount = _min(_amount, _creditBalance);
                creditBalances[_jobId] -= _creditAmount;
                creditToken.redeemAndBurn(_to, _creditAmount);
                emit MarketCreditTokenSettled(_jobId, _now(), _to, _creditAmount);
            }
        }

        if (_amount > _creditAmount) {
            uint64 _tokenAmount = _amount - _creditAmount;
            token.safeTransfer(_to, _tokenAmount);
            emit MarketTokenSettled(_jobId, _now(), _to, _tokenAmount);
        }
    }

    function _withdraw(uint64 _jobId, uint64 _jobBalance, address _to, uint64 _amount) internal {
        uint64 _jobTokenBalance = _jobBalance - creditBalances[_jobId];
        uint64 _tokenAmount = _min(_jobTokenBalance, _amount);

        if (_tokenAmount > 0) {
            token.safeTransfer(_to, _tokenAmount);
            emit MarketTokenWithdrew(_jobId, _now(), _to, _tokenAmount);
        }

        if (_amount > _tokenAmount) {
            uint64 _creditAmount = _amount - _tokenAmount;
            creditBalances[_jobId] -= _creditAmount;
            creditToken.safeTransfer(_to, _creditAmount);
            emit MarketCreditTokenWithdrew(_jobId, _now(), _to, _creditAmount);
        }
    }

    function _withdrawAllCredit(uint64 _jobId, address _to) internal returns (uint64 _creditAmount) {
        _creditAmount = creditBalances[_jobId];
        creditBalances[_jobId] = 0;
        creditToken.safeTransfer(_to, _creditAmount);
        emit MarketCreditTokenWithdrew(_jobId, _now(), _to, _creditAmount);
    }

    /*---- Payments end ----*/
}
