// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test} from "../Test.sol";
import {Erc165Test} from "../Erc165Test.sol";
import {IERC165} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";
import {IAccessControl} from "@openzeppelin/contracts/access/IAccessControl.sol";
import {RbacAdminTest, RbacRoleTest} from "../RbacTest.sol";
import {Initializable} from "@openzeppelin/contracts/proxy/utils/Initializable.sol";
import {Upgrades} from "openzeppelin-foundry-upgrades/Upgrades.sol";
import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {Market} from "../../src/market/Market.sol";
import {ICredit} from "../../src/token/ICredit.sol";
import {ERC165Upgradeable} from "@openzeppelin/contracts-upgradeable/utils/introspection/ERC165Upgradeable.sol";
import {IERC20Errors} from "@openzeppelin/contracts/interfaces/draft-IERC6093.sol";

contract ERC20Mock is ERC20 {
    constructor(string memory name, string memory symbol) ERC20(name, symbol) {}

    function mint(address account, uint256 amount) public {
        _mint(account, amount);
    }
}

contract CreditMock is ERC20Mock, ICredit {
    ERC20Mock public usdc;

    constructor(ERC20Mock _usdc) ERC20Mock("Credit", "CREDIT") {
        usdc = _usdc;
    }

    function redeemAndBurn(address to, uint256 amount) external {
        _burn(msg.sender, amount);
        usdc.transfer(to, amount);
    }
}

library Utils {
    uint256 public constant ONE_MINUTE = 60;
    uint256 public constant TWO_MINUTES = ONE_MINUTE * 2;
    uint256 public constant FIVE_MINUTES = ONE_MINUTE * 5;
    uint256 public constant NOTICE_PERIOD = FIVE_MINUTES;

    uint256 public constant SIGNER1_INITIAL_FUND = 1000 * 10 ** 6;
    uint256 public constant SIGNER2_INITIAL_FUND = 1000 * 10 ** 6;
    uint256 public constant JOB_RATE = 2 * 10 ** 16; // 0.02 USDC/s

    function calcAmountToPay(uint256 rate, uint256 duration) internal pure returns (uint256) {
        uint256 decimals = 10 ** 12;
        return (rate * duration + decimals - 1) / decimals;
    }

    function usdc(uint256 amount) internal pure returns (uint256) {
        return amount * 10 ** 6;
    }
}

abstract contract MarketTest is Test {
    function assertEq(Market _market, uint64 _jobId, Market.Job memory _job) public {
        (
            string memory _jobMetadata,
            address _jobOwner,
            address _jobProvider,
            uint256 _jobRate,
            uint256 _jobBalance,
            uint256 _jobLastSettled,
            uint256 _jobMaxRate
        ) = _market.jobs(_jobId);
        assertEq(_jobMetadata, _job.metadata);
        assertEq(_jobOwner, _job.owner);
        assertEq(_jobProvider, _job.provider);
        assertEq(_jobRate, _job.rate);
        assertEq(_jobBalance, _job.balance);
        assertEq(_jobLastSettled, _job.lastSettled);
        assertEq(_jobMaxRate, _job.maxRate);
    }
}

contract MarketErc165Test is Erc165Test {
    function _erc165DeployContract() internal virtual override returns (IERC165) {
        return IERC165(
            Upgrades.deployUUPSProxy(
                "Market.sol",
                abi.encodeCall(
                    Market.initialize,
                    (vm.randomAddress(), 1234, Utils.NOTICE_PERIOD, vm.randomAddress(), vm.randomAddress())
                ),
                upgradeOptions()
            )
        );
    }

    function _erc165GetInterfaces() internal virtual override returns (bytes4[] memory) {
        bytes4[] memory interfaces = new bytes4[](1);
        interfaces[0] = type(IAccessControl).interfaceId;
    }
}

contract MarketRbacAdminTest is RbacAdminTest {
    function _rbacAdminDeployContract(address _admin) internal virtual override returns (IAccessControl) {
        return IAccessControl(
            Upgrades.deployUUPSProxy(
                "Market.sol",
                abi.encodeCall(
                    Market.initialize, (_admin, 1234, Utils.NOTICE_PERIOD, vm.randomAddress(), vm.randomAddress())
                ),
                upgradeOptions()
            )
        );
    }
}

contract MarketTestDeploy is Test {
    function deployHelper(address _admin, address _usdc, address _credit, uint64 _jobId) public returns (Market) {
        return Market(
            Upgrades.deployUUPSProxy(
                "Market.sol",
                abi.encodeCall(Market.initialize, (_admin, _jobId, Utils.NOTICE_PERIOD, _usdc, _credit)),
                upgradeOptions()
            )
        );
    }

    function upgradeHelper(address _proxy) public {
        vm.startPrank(msg.sender);
        Upgrades.upgradeProxy(_proxy, "Market.sol", "", upgradeOptions());
        vm.stopPrank();
    }

    function test_Deploy_InitializationDisabled() public {
        Market _market = new Market();
        vm.expectRevert(Initializable.InvalidInitialization.selector);
        _market.initialize(vm.randomAddress(), 1234, Utils.NOTICE_PERIOD, vm.randomAddress(), vm.randomAddress());
    }

    function test_Deploy_WithProxy(address _admin, address _usdc, address _credit, uint64 _jobId)
        public
        assumeNotEqualAddress(address(this), _admin)
    {
        vm.expectEmit();
        emit IAccessControl.RoleGranted(bytes32(0), _admin, address(this));
        vm.expectEmit();
        emit Market.MarketNoticePeriodUpdated(0, Utils.NOTICE_PERIOD);
        vm.expectEmit();
        emit Market.MarketTokenUpdated(address(0), _usdc);
        vm.expectEmit();
        emit Market.MarketCreditTokenUpdated(address(0), _credit);
        Market _market = this.deployHelper(_admin, _usdc, _credit, _jobId);

        assertTrue(_market.hasRole(_market.DEFAULT_ADMIN_ROLE(), _admin));
        assertFalse(_market.hasRole(_market.DEFAULT_ADMIN_ROLE(), address(this)));
        assertEq(_market.jobIndex(), _jobId);
        assertEq(_market.noticePeriod(), Utils.NOTICE_PERIOD);
        assertEq(address(_market.token()), _usdc);
        assertEq(address(_market.creditToken()), _credit);
    }

    function test_Deploy_AdminCanUpgrade(address _admin, address _usdc, address _credit, uint64 _jobId)
        public
        assumeNotEqualAddress(address(this), _admin)
    {
        vm.expectEmit();
        emit IAccessControl.RoleGranted(bytes32(0), _admin, address(this));
        vm.expectEmit();
        emit Market.MarketNoticePeriodUpdated(0, Utils.NOTICE_PERIOD);
        vm.expectEmit();
        emit Market.MarketTokenUpdated(address(0), _usdc);
        vm.expectEmit();
        emit Market.MarketCreditTokenUpdated(address(0), _credit);
        Market _market = this.deployHelper(_admin, _usdc, _credit, _jobId);

        assertTrue(_market.hasRole(_market.DEFAULT_ADMIN_ROLE(), _admin));
        assertFalse(_market.hasRole(_market.DEFAULT_ADMIN_ROLE(), address(this)));
        assertEq(_market.jobIndex(), _jobId);
        assertEq(_market.noticePeriod(), Utils.NOTICE_PERIOD);
        assertEq(address(_market.token()), _usdc);
        assertEq(address(_market.creditToken()), _credit);

        vm.startPrank(_admin);
        this.upgradeHelper(address(_market));
        vm.stopPrank();

        assertTrue(_market.hasRole(_market.DEFAULT_ADMIN_ROLE(), _admin));
        assertFalse(_market.hasRole(_market.DEFAULT_ADMIN_ROLE(), address(this)));
        assertEq(_market.jobIndex(), _jobId);
        assertEq(_market.noticePeriod(), Utils.NOTICE_PERIOD);
        assertEq(address(_market.token()), _usdc);
        assertEq(address(_market.creditToken()), _credit);
    }

    function test_Deploy_NonAdminCannotUpgrade(address _admin, address _usdc, address _credit, uint64 _jobId)
        public
        assumeNotEqualAddress(address(this), _admin)
    {
        vm.expectEmit();
        emit IAccessControl.RoleGranted(bytes32(0), _admin, address(this));
        vm.expectEmit();
        emit Market.MarketNoticePeriodUpdated(0, Utils.NOTICE_PERIOD);
        vm.expectEmit();
        emit Market.MarketTokenUpdated(address(0), _usdc);
        vm.expectEmit();
        emit Market.MarketCreditTokenUpdated(address(0), _credit);
        Market _market = this.deployHelper(_admin, _usdc, _credit, _jobId);

        assertTrue(_market.hasRole(_market.DEFAULT_ADMIN_ROLE(), _admin));
        assertFalse(_market.hasRole(_market.DEFAULT_ADMIN_ROLE(), address(this)));
        assertEq(_market.jobIndex(), _jobId);
        assertEq(_market.noticePeriod(), Utils.NOTICE_PERIOD);
        assertEq(address(_market.token()), _usdc);
        assertEq(address(_market.creditToken()), _credit);

        vm.expectRevert(Market.MarketOnlyAdmin.selector);
        this.upgradeHelper(address(_market));
    }
}

contract MarketTestProviderAdd is Test {
    Market market;

    function setUp() public {
        market = Market(
            Upgrades.deployUUPSProxy(
                "Market.sol",
                abi.encodeCall(
                    Market.initialize,
                    (
                        vm.randomAddress(),
                        uint64(vm.randomUint()),
                        Utils.NOTICE_PERIOD,
                        vm.randomAddress(),
                        vm.randomAddress()
                    )
                ),
                upgradeOptions()
            )
        );
    }

    function test_ProviderAdd_Valid(address _provider, string memory _cp) public assumeNonEmptyString(_cp) {
        vm.expectEmit();
        emit Market.MarketProviderAdded(_provider, _cp);
        vm.prank(_provider);
        market.providerAdd(_cp);

        assertEq(market.providers(_provider), _cp);
    }

    function test_ProviderAdd_EmptyCp(address _provider) public {
        vm.prank(_provider);
        vm.expectRevert(Market.MarketProviderInvalidCp.selector);
        market.providerAdd("");
    }

    function test_ProviderAdd_AlreadyRegistered(address _provider, string memory _cp) public assumeNonEmptyString(_cp) {
        vm.prank(_provider);
        market.providerAdd(_cp);

        vm.prank(_provider);
        vm.expectRevert(Market.MarketProviderAlreadyExists.selector);
        market.providerAdd(_cp);
    }
}

contract MarketTestProviderRemove is Test {
    Market market;

    function setUp() public {
        market = Market(
            Upgrades.deployUUPSProxy(
                "Market.sol",
                abi.encodeCall(
                    Market.initialize,
                    (
                        vm.randomAddress(),
                        uint64(vm.randomUint()),
                        Utils.NOTICE_PERIOD,
                        vm.randomAddress(),
                        vm.randomAddress()
                    )
                ),
                upgradeOptions()
            )
        );
    }

    function test_ProviderRemove_Valid(address _provider, string memory _cp) public assumeNonEmptyString(_cp) {
        vm.prank(_provider);
        market.providerAdd(_cp);
        assertEq(market.providers(_provider), _cp);

        vm.expectEmit();
        emit Market.MarketProviderRemoved(_provider);
        vm.prank(_provider);
        market.providerRemove();

        assertEq(market.providers(_provider), "");
    }

    function test_ProviderRemove_NeverRegistered(address _provider) public {
        vm.prank(_provider);
        vm.expectRevert(Market.MarketProviderNotFound.selector);
        market.providerRemove();
    }

    function test_ProviderRemove_Unregistered(address _provider, string memory _cp) public assumeNonEmptyString(_cp) {
        vm.prank(_provider);
        market.providerAdd(_cp);
        assertEq(market.providers(_provider), _cp);
        vm.prank(_provider);
        market.providerRemove();
        assertEq(market.providers(_provider), "");

        vm.prank(_provider);
        vm.expectRevert(Market.MarketProviderNotFound.selector);
        market.providerRemove();
    }
}

contract MarketTestProviderUpdate is Test {
    Market market;

    function setUp() public {
        market = Market(
            Upgrades.deployUUPSProxy(
                "Market.sol",
                abi.encodeCall(
                    Market.initialize,
                    (
                        vm.randomAddress(),
                        uint64(vm.randomUint()),
                        Utils.NOTICE_PERIOD,
                        vm.randomAddress(),
                        vm.randomAddress()
                    )
                ),
                upgradeOptions()
            )
        );
    }

    function test_ProviderUpdate_Valid(address _provider, string memory _cp, string memory _newCp)
        public
        assumeNonEmptyString(_cp)
        assumeNonEmptyString(_newCp)
    {
        vm.prank(_provider);
        market.providerAdd(_cp);
        assertEq(market.providers(_provider), _cp);

        vm.expectEmit();
        emit Market.MarketProviderUpdated(_provider, _cp, _newCp);
        vm.prank(_provider);
        market.providerUpdate(_newCp);

        assertEq(market.providers(_provider), _newCp);
    }

    function test_ProviderUpdate_EmptyCp(address _provider, string memory _cp) public assumeNonEmptyString(_cp) {
        vm.prank(_provider);
        market.providerAdd(_cp);
        assertEq(market.providers(_provider), _cp);

        vm.expectRevert(Market.MarketProviderInvalidCp.selector);
        vm.prank(_provider);
        market.providerUpdate("");
    }

    function test_ProviderUpdate_Unregistered(address _provider, string memory _newCp)
        public
        assumeNonEmptyString(_newCp)
    {
        vm.prank(_provider);
        vm.expectRevert(Market.MarketProviderNotFound.selector);
        market.providerUpdate(_newCp);
    }
}

contract MarketTestUpdateNoticePeriod is Test {
    Market market;
    address admin;

    function setUp() public {
        admin = vm.randomAddress();
        market = Market(
            Upgrades.deployUUPSProxy(
                "Market.sol",
                abi.encodeCall(
                    Market.initialize,
                    (admin, uint64(vm.randomUint()), Utils.NOTICE_PERIOD, vm.randomAddress(), vm.randomAddress())
                ),
                upgradeOptions()
            )
        );
    }

    function test_UpdateNoticePeriod_Admin(uint256 _newNoticePeriod) public {
        vm.expectEmit();
        emit Market.MarketNoticePeriodUpdated(Utils.NOTICE_PERIOD, _newNoticePeriod);
        vm.prank(admin);
        market.updateNoticePeriod(_newNoticePeriod);

        assertEq(market.noticePeriod(), _newNoticePeriod);
    }

    function test_UpdateNoticePeriod_NonAdmin(uint256 _newNoticePeriod) public {
        vm.expectRevert(Market.MarketOnlyAdmin.selector);
        market.updateNoticePeriod(_newNoticePeriod);
    }
}

contract MarketTestJobOpen is MarketTest {
    Market market;
    ERC20Mock usdc;
    CreditMock credit;
    uint256 creditTokenBalance;
    uint64 jobId;

    function setUp() public {
        usdc = new ERC20Mock("Circle USD", "USDC");
        credit = new CreditMock(usdc);
        creditTokenBalance = Utils.usdc(1000);
        usdc.mint(address(credit), creditTokenBalance);
        jobId = uint64(vm.randomUint(0, 10000));
        market = Market(
            Upgrades.deployUUPSProxy(
                "Market.sol",
                abi.encodeCall(
                    Market.initialize, (vm.randomAddress(), jobId, Utils.NOTICE_PERIOD, address(usdc), address(credit))
                ),
                upgradeOptions()
            )
        );
    }

    function _assumptions(address _user, address _provider)
        internal
        assumeNonZeroAddress(_user)
        assumeNonZeroAddress(_provider)
        assumeNotEqualAddress(_user, _provider)
        assumeNotEqualAddress(_user, address(market))
        assumeNotEqualAddress(_provider, address(market))
        assumeNotEqualAddress(_user, address(credit))
        assumeNotEqualAddress(_provider, address(credit))
    {}

    function test_JobOpen_OnlyUSDC(address _user, address _provider, string memory _metadata) public {
        _assumptions(_user, _provider);

        uint256 _initialBalance = Utils.usdc(50);
        usdc.mint(_user, _initialBalance);
        uint256 _noticePeriodCost = Utils.calcAmountToPay(Utils.JOB_RATE, Utils.NOTICE_PERIOD);

        vm.startPrank(_user);
        usdc.approve(address(market), _initialBalance);
        vm.expectEmit();
        emit Market.MarketJobOpened(jobId, block.timestamp, _metadata, _user, _provider);
        vm.expectEmit();
        emit Market.MarketTokenDeposited(jobId, block.timestamp, _user, _initialBalance);
        vm.expectEmit();
        emit Market.MarketJobDeposited(jobId, block.timestamp, _initialBalance, _user);
        vm.expectEmit();
        emit Market.MarketTokenSettled(jobId, block.timestamp, _provider, _noticePeriodCost);
        vm.expectEmit();
        emit Market.MarketJobSettled(jobId, block.timestamp, _noticePeriodCost, _provider);
        vm.expectEmit();
        emit Market.MarketJobRateRevised(jobId, block.timestamp, Utils.JOB_RATE);
        market.jobOpen(_metadata, _provider, Utils.JOB_RATE, _initialBalance);
        vm.stopPrank();

        assertEq(
            market,
            jobId,
            Market.Job(
                _metadata,
                _user,
                _provider,
                Utils.JOB_RATE,
                _initialBalance - _noticePeriodCost,
                block.timestamp,
                Utils.JOB_RATE
            )
        );

        assertEq(market.creditBalances(jobId), 0);

        assertEq(usdc.balanceOf(_user), 0);
        assertEq(usdc.balanceOf(address(market)), _initialBalance - _noticePeriodCost);
        assertEq(usdc.balanceOf(_provider), _noticePeriodCost);
        assertEq(usdc.balanceOf(address(credit)), creditTokenBalance);
        assertEq(credit.balanceOf(_user), 0);
        assertEq(credit.balanceOf(address(market)), 0);
        assertEq(credit.balanceOf(_provider), 0);

        assertEq(market.jobIndex(), jobId + 1);
    }

    function test_JobOpen_OnlyCredit(address _user, address _provider, string memory _metadata) public {
        _assumptions(_user, _provider);

        uint256 _initialBalance = Utils.usdc(50);
        credit.mint(_user, _initialBalance);
        uint256 _noticePeriodCost = Utils.calcAmountToPay(Utils.JOB_RATE, Utils.NOTICE_PERIOD);

        vm.startPrank(_user);
        credit.approve(address(market), _initialBalance);
        vm.expectEmit();
        emit Market.MarketJobOpened(jobId, block.timestamp, _metadata, _user, _provider);
        vm.expectEmit();
        emit Market.MarketCreditTokenDeposited(jobId, block.timestamp, _user, _initialBalance);
        vm.expectEmit();
        emit Market.MarketJobDeposited(jobId, block.timestamp, _initialBalance, _user);
        vm.expectEmit();
        emit Market.MarketCreditTokenSettled(jobId, block.timestamp, _provider, _noticePeriodCost);
        vm.expectEmit();
        emit Market.MarketJobSettled(jobId, block.timestamp, _noticePeriodCost, _provider);
        vm.expectEmit();
        emit Market.MarketJobRateRevised(jobId, block.timestamp, Utils.JOB_RATE);
        market.jobOpen(_metadata, _provider, Utils.JOB_RATE, _initialBalance);
        vm.stopPrank();

        assertEq(
            market,
            jobId,
            Market.Job(
                _metadata,
                _user,
                _provider,
                Utils.JOB_RATE,
                _initialBalance - _noticePeriodCost,
                block.timestamp,
                Utils.JOB_RATE
            )
        );

        assertEq(market.creditBalances(jobId), _initialBalance - _noticePeriodCost);

        assertEq(usdc.balanceOf(_user), 0);
        assertEq(usdc.balanceOf(address(market)), 0);
        assertEq(usdc.balanceOf(_provider), _noticePeriodCost);
        assertEq(usdc.balanceOf(address(credit)), creditTokenBalance - _noticePeriodCost);
        assertEq(credit.balanceOf(_user), 0);
        assertEq(credit.balanceOf(address(market)), _initialBalance - _noticePeriodCost);
        assertEq(credit.balanceOf(_provider), 0);

        assertEq(market.jobIndex(), jobId + 1);
    }

    function test_JobOpen_USDCAndCredit(address _user, address _provider, string memory _metadata) public {
        _assumptions(_user, _provider);

        uint256 _initialBalance = Utils.usdc(50);
        uint256 _initialTokenBalance = Utils.usdc(20);
        uint256 _initialCreditBalance = Utils.usdc(30);
        usdc.mint(_user, _initialTokenBalance);
        credit.mint(_user, _initialCreditBalance);
        uint256 _noticePeriodCost = Utils.calcAmountToPay(Utils.JOB_RATE, Utils.NOTICE_PERIOD);

        vm.startPrank(_user);
        usdc.approve(address(market), _initialTokenBalance);
        credit.approve(address(market), _initialCreditBalance);
        vm.expectEmit();
        emit Market.MarketJobOpened(jobId, block.timestamp, _metadata, _user, _provider);
        vm.expectEmit();
        emit Market.MarketCreditTokenDeposited(jobId, block.timestamp, _user, _initialCreditBalance);
        emit Market.MarketTokenDeposited(jobId, block.timestamp, _user, _initialTokenBalance);
        vm.expectEmit();
        emit Market.MarketJobDeposited(jobId, block.timestamp, _initialBalance, _user);
        vm.expectEmit();
        emit Market.MarketCreditTokenSettled(jobId, block.timestamp, _provider, _noticePeriodCost);
        vm.expectEmit();
        emit Market.MarketJobSettled(jobId, block.timestamp, _noticePeriodCost, _provider);
        vm.expectEmit();
        emit Market.MarketJobRateRevised(jobId, block.timestamp, Utils.JOB_RATE);
        market.jobOpen(_metadata, _provider, Utils.JOB_RATE, _initialBalance);
        vm.stopPrank();

        assertEq(
            market,
            jobId,
            Market.Job(
                _metadata,
                _user,
                _provider,
                Utils.JOB_RATE,
                _initialBalance - _noticePeriodCost,
                block.timestamp,
                Utils.JOB_RATE
            )
        );

        assertEq(market.creditBalances(jobId), _initialCreditBalance - _noticePeriodCost);

        assertEq(usdc.balanceOf(_user), 0);
        assertEq(usdc.balanceOf(address(market)), _initialTokenBalance);
        assertEq(usdc.balanceOf(_provider), _noticePeriodCost);
        assertEq(usdc.balanceOf(address(credit)), creditTokenBalance - _noticePeriodCost);
        assertEq(credit.balanceOf(_user), 0);
        assertEq(credit.balanceOf(address(market)), _initialCreditBalance - _noticePeriodCost);
        assertEq(credit.balanceOf(_provider), 0);

        assertEq(market.jobIndex(), jobId + 1);
    }

    function test_JobOpen_NotEnoughUSDC(address _user, address _provider, string memory _metadata) public {
        _assumptions(_user, _provider);

        uint256 _initialBalance = Utils.usdc(50);
        uint256 _initialTokenBalance = Utils.usdc(10);
        uint256 _initialCreditBalance = Utils.usdc(30);
        usdc.mint(_user, _initialTokenBalance);
        credit.mint(_user, _initialCreditBalance);

        vm.startPrank(_user);
        usdc.approve(address(market), _initialBalance);
        credit.approve(address(market), _initialBalance);
        vm.expectRevert(
            abi.encodeWithSelector(
                IERC20Errors.ERC20InsufficientBalance.selector, _user, _initialTokenBalance, Utils.usdc(20)
            )
        );
        market.jobOpen(_metadata, _provider, Utils.JOB_RATE, _initialBalance);
        vm.stopPrank();
    }

    function test_JobOpen_NotEnoughCredit(address _user, address _provider, string memory _metadata) public {
        _assumptions(_user, _provider);

        uint256 _initialBalance = Utils.usdc(50);
        uint256 _initialTokenBalance = Utils.usdc(20);
        uint256 _initialCreditBalance = Utils.usdc(20);
        usdc.mint(_user, _initialTokenBalance);
        credit.mint(_user, _initialCreditBalance);

        vm.startPrank(_user);
        usdc.approve(address(market), _initialBalance);
        credit.approve(address(market), _initialBalance);
        vm.expectRevert(
            abi.encodeWithSelector(
                IERC20Errors.ERC20InsufficientBalance.selector, _user, _initialTokenBalance, Utils.usdc(30)
            )
        );
        market.jobOpen(_metadata, _provider, Utils.JOB_RATE, _initialBalance);
        vm.stopPrank();
    }
}

contract MarketTestJobOpenNoCredit is MarketTest {
    Market market;
    ERC20Mock usdc;
    uint64 jobId;

    function setUp() public {
        usdc = new ERC20Mock("Circle USD", "USDC");
        jobId = uint64(vm.randomUint(0, 10000));
        market = Market(
            Upgrades.deployUUPSProxy(
                "Market.sol",
                abi.encodeCall(
                    Market.initialize, (vm.randomAddress(), jobId, Utils.NOTICE_PERIOD, address(usdc), address(0))
                ),
                upgradeOptions()
            )
        );
    }

    function _assumptions(address _user, address _provider)
        internal
        assumeNonZeroAddress(_user)
        assumeNonZeroAddress(_provider)
        assumeNotEqualAddress(_user, _provider)
        assumeNotEqualAddress(_user, address(market))
        assumeNotEqualAddress(_provider, address(market))
    {}

    function test_JobOpen_OnlyUSDC(address _user, address _provider, string memory _metadata) public {
        _assumptions(_user, _provider);

        uint256 _initialBalance = Utils.usdc(50);
        usdc.mint(_user, _initialBalance);
        uint256 _noticePeriodCost = Utils.calcAmountToPay(Utils.JOB_RATE, Utils.NOTICE_PERIOD);

        vm.startPrank(_user);
        usdc.approve(address(market), _initialBalance);
        vm.expectEmit();
        emit Market.MarketJobOpened(jobId, block.timestamp, _metadata, _user, _provider);
        vm.expectEmit();
        emit Market.MarketTokenDeposited(jobId, block.timestamp, _user, _initialBalance);
        vm.expectEmit();
        emit Market.MarketJobDeposited(jobId, block.timestamp, _initialBalance, _user);
        vm.expectEmit();
        emit Market.MarketTokenSettled(jobId, block.timestamp, _provider, _noticePeriodCost);
        vm.expectEmit();
        emit Market.MarketJobSettled(jobId, block.timestamp, _noticePeriodCost, _provider);
        vm.expectEmit();
        emit Market.MarketJobRateRevised(jobId, block.timestamp, Utils.JOB_RATE);
        market.jobOpen(_metadata, _provider, Utils.JOB_RATE, _initialBalance);
        vm.stopPrank();

        assertEq(
            market,
            jobId,
            Market.Job(
                _metadata,
                _user,
                _provider,
                Utils.JOB_RATE,
                _initialBalance - _noticePeriodCost,
                block.timestamp,
                Utils.JOB_RATE
            )
        );

        assertEq(market.creditBalances(jobId), 0);

        assertEq(usdc.balanceOf(_user), 0);
        assertEq(usdc.balanceOf(address(market)), _initialBalance - _noticePeriodCost);
        assertEq(usdc.balanceOf(_provider), _noticePeriodCost);

        assertEq(market.jobIndex(), jobId + 1);
    }

    function test_JobOpen_NotEnoughUSDC(address _user, address _provider, string memory _metadata) public {
        _assumptions(_user, _provider);

        uint256 _initialBalance = Utils.usdc(50);
        uint256 _initialTokenBalance = Utils.usdc(10);
        usdc.mint(_user, _initialTokenBalance);

        vm.startPrank(_user);
        usdc.approve(address(market), _initialBalance);
        vm.expectRevert(
            abi.encodeWithSelector(
                IERC20Errors.ERC20InsufficientBalance.selector, _user, _initialTokenBalance, Utils.usdc(50)
            )
        );
        market.jobOpen(_metadata, _provider, Utils.JOB_RATE, _initialBalance);
        vm.stopPrank();
    }
}

contract MarketTestJobSettle is MarketTest {
    Market market;
    ERC20Mock usdc;
    CreditMock credit;
    uint256 creditTokenBalance;
    uint64 jobId;

    function setUp() public {
        usdc = new ERC20Mock("Circle USD", "USDC");
        credit = new CreditMock(usdc);
        creditTokenBalance = Utils.usdc(1000);
        usdc.mint(address(credit), creditTokenBalance);
        jobId = uint64(vm.randomUint(0, 10000));
        market = Market(
            Upgrades.deployUUPSProxy(
                "Market.sol",
                abi.encodeCall(
                    Market.initialize, (vm.randomAddress(), jobId, Utils.NOTICE_PERIOD, address(usdc), address(credit))
                ),
                upgradeOptions()
            )
        );
    }

    function _assumptions(address _user, address _provider)
        internal
        assumeNonZeroAddress(_user)
        assumeNonZeroAddress(_provider)
        assumeNotEqualAddress(_user, _provider)
        assumeNotEqualAddress(_user, address(market))
        assumeNotEqualAddress(_provider, address(market))
        assumeNotEqualAddress(_user, address(credit))
        assumeNotEqualAddress(_provider, address(credit))
    {}

    function test_JobSettle_OnlyUSDC(address _user, address _provider, string memory _metadata) public {
        _assumptions(_user, _provider);

        uint256 _initialBalance = Utils.usdc(50);
        usdc.mint(_user, _initialBalance);
        uint256 _noticePeriodCost = Utils.calcAmountToPay(Utils.JOB_RATE, Utils.NOTICE_PERIOD);

        vm.startPrank(_user);
        usdc.approve(address(market), _initialBalance);
        market.jobOpen(_metadata, _provider, Utils.JOB_RATE, _initialBalance);
        vm.stopPrank();

        skip(2000);
        uint256 _settleAmount = Utils.usdc(40);
        vm.expectEmit();
        emit Market.MarketTokenSettled(jobId, block.timestamp, _provider, _settleAmount);
        vm.expectEmit();
        emit Market.MarketJobSettled(jobId, block.timestamp, _settleAmount, _provider);
        market.jobSettle(jobId);

        assertEq(
            market,
            jobId,
            Market.Job(
                _metadata,
                _user,
                _provider,
                Utils.JOB_RATE,
                _initialBalance - _noticePeriodCost - _settleAmount,
                block.timestamp,
                Utils.JOB_RATE
            )
        );

        assertEq(market.creditBalances(jobId), 0);

        assertEq(usdc.balanceOf(_user), 0);
        assertEq(usdc.balanceOf(address(market)), _initialBalance - _noticePeriodCost - _settleAmount);
        assertEq(usdc.balanceOf(_provider), _noticePeriodCost + _settleAmount);
    }

    function test_JobSettle_OnlyCredit(address _user, address _provider, string memory _metadata) public {
        _assumptions(_user, _provider);

        uint256 _initialBalance = Utils.usdc(50);
        credit.mint(_user, _initialBalance);
        uint256 _noticePeriodCost = Utils.calcAmountToPay(Utils.JOB_RATE, Utils.NOTICE_PERIOD);

        vm.startPrank(_user);
        credit.approve(address(market), _initialBalance);
        market.jobOpen(_metadata, _provider, Utils.JOB_RATE, _initialBalance);
        vm.stopPrank();

        skip(2000);
        uint256 _settleAmount = Utils.usdc(40);
        vm.expectEmit();
        emit Market.MarketCreditTokenSettled(jobId, block.timestamp, _provider, _settleAmount);
        vm.expectEmit();
        emit Market.MarketJobSettled(jobId, block.timestamp, _settleAmount, _provider);
        market.jobSettle(jobId);

        assertEq(
            market,
            jobId,
            Market.Job(
                _metadata,
                _user,
                _provider,
                Utils.JOB_RATE,
                _initialBalance - _noticePeriodCost - _settleAmount,
                block.timestamp,
                Utils.JOB_RATE
            )
        );

        assertEq(market.creditBalances(jobId), _initialBalance - _noticePeriodCost - _settleAmount);

        assertEq(usdc.balanceOf(_user), 0);
        assertEq(usdc.balanceOf(address(market)), 0);
        assertEq(usdc.balanceOf(_provider), _noticePeriodCost + _settleAmount);
        assertEq(usdc.balanceOf(address(credit)), creditTokenBalance - _noticePeriodCost - _settleAmount);
        assertEq(credit.balanceOf(_user), 0);
        assertEq(credit.balanceOf(address(market)), _initialBalance - _noticePeriodCost - _settleAmount);
        assertEq(credit.balanceOf(_provider), 0);
    }

    function test_JobSettle_USDCAndCredit(address _user, address _provider, string memory _metadata) public {
        _assumptions(_user, _provider);

        uint256 _initialBalance = Utils.usdc(50);
        uint256 _initialTokenBalance = Utils.usdc(20);
        uint256 _initialCreditBalance = Utils.usdc(30);
        usdc.mint(_user, _initialTokenBalance);
        credit.mint(_user, _initialCreditBalance);
        uint256 _noticePeriodCost = Utils.calcAmountToPay(Utils.JOB_RATE, Utils.NOTICE_PERIOD);

        vm.startPrank(_user);
        usdc.approve(address(market), _initialTokenBalance);
        credit.approve(address(market), _initialCreditBalance);
        market.jobOpen(_metadata, _provider, Utils.JOB_RATE, _initialBalance);
        vm.stopPrank();

        skip(2000);
        uint256 _settleAmount = Utils.usdc(40);
        uint256 _tokenSettleAmount = Utils.usdc(10) + _noticePeriodCost;
        uint256 _creditSettleAmount = Utils.usdc(30) - _noticePeriodCost;
        vm.expectEmit();
        emit Market.MarketCreditTokenSettled(jobId, block.timestamp, _provider, _creditSettleAmount);
        vm.expectEmit();
        emit Market.MarketTokenSettled(jobId, block.timestamp, _provider, _tokenSettleAmount);
        vm.expectEmit();
        emit Market.MarketJobSettled(jobId, block.timestamp, _settleAmount, _provider);
        market.jobSettle(jobId);

        assertEq(
            market,
            jobId,
            Market.Job(
                _metadata,
                _user,
                _provider,
                Utils.JOB_RATE,
                _initialBalance - _noticePeriodCost - _settleAmount,
                block.timestamp,
                Utils.JOB_RATE
            )
        );

        assertEq(market.creditBalances(jobId), _initialCreditBalance - _noticePeriodCost - _creditSettleAmount);

        assertEq(usdc.balanceOf(_user), 0);
        assertEq(usdc.balanceOf(address(market)), _initialTokenBalance - _tokenSettleAmount);
        assertEq(usdc.balanceOf(_provider), _noticePeriodCost + _settleAmount);
        assertEq(usdc.balanceOf(address(credit)), creditTokenBalance - _noticePeriodCost - _creditSettleAmount);
        assertEq(credit.balanceOf(_user), 0);
        assertEq(credit.balanceOf(address(market)), _initialCreditBalance - _noticePeriodCost - _creditSettleAmount);
        assertEq(credit.balanceOf(_provider), 0);
    }

    function test_JobSettle_NotEnoughBalance(address _user, address _provider, string memory _metadata) public {
        _assumptions(_user, _provider);

        uint256 _initialBalance = Utils.usdc(50);
        uint256 _initialTokenBalance = Utils.usdc(20);
        uint256 _initialCreditBalance = Utils.usdc(30);
        usdc.mint(_user, _initialTokenBalance);
        credit.mint(_user, _initialCreditBalance);
        uint256 _noticePeriodCost = Utils.calcAmountToPay(Utils.JOB_RATE, Utils.NOTICE_PERIOD);

        vm.startPrank(_user);
        usdc.approve(address(market), _initialTokenBalance);
        credit.approve(address(market), _initialCreditBalance);
        market.jobOpen(_metadata, _provider, Utils.JOB_RATE, _initialBalance);
        vm.stopPrank();

        skip(3000);
        uint256 _settleAmount = Utils.usdc(50) - _noticePeriodCost;
        uint256 _tokenSettleAmount = _initialTokenBalance;
        uint256 _creditSettleAmount = _initialCreditBalance - _noticePeriodCost;
        vm.expectEmit();
        emit Market.MarketCreditTokenSettled(jobId, block.timestamp, _provider, _creditSettleAmount);
        vm.expectEmit();
        emit Market.MarketTokenSettled(jobId, block.timestamp, _provider, _tokenSettleAmount);
        vm.expectEmit();
        emit Market.MarketJobSettled(jobId, block.timestamp, _settleAmount, _provider);
        market.jobSettle(jobId);

        assertEq(
            market,
            jobId,
            Market.Job(
                _metadata,
                _user,
                _provider,
                Utils.JOB_RATE,
                _initialBalance - _noticePeriodCost - _settleAmount,
                block.timestamp,
                Utils.JOB_RATE
            )
        );

        assertEq(market.creditBalances(jobId), _initialCreditBalance - _noticePeriodCost - _creditSettleAmount);

        assertEq(usdc.balanceOf(_user), 0);
        assertEq(usdc.balanceOf(address(market)), _initialTokenBalance - _tokenSettleAmount);
        assertEq(usdc.balanceOf(_provider), _noticePeriodCost + _settleAmount);
        assertEq(usdc.balanceOf(address(credit)), creditTokenBalance - _noticePeriodCost - _creditSettleAmount);
        assertEq(credit.balanceOf(_user), 0);
        assertEq(credit.balanceOf(address(market)), _initialCreditBalance - _noticePeriodCost - _creditSettleAmount);
        assertEq(credit.balanceOf(_provider), 0);
    }
}

contract MarketTestJobSettleNoCredit is MarketTest {
    Market market;
    ERC20Mock usdc;
    uint64 jobId;

    function setUp() public {
        usdc = new ERC20Mock("Circle USD", "USDC");
        jobId = uint64(vm.randomUint(0, 10000));
        market = Market(
            Upgrades.deployUUPSProxy(
                "Market.sol",
                abi.encodeCall(
                    Market.initialize, (vm.randomAddress(), jobId, Utils.NOTICE_PERIOD, address(usdc), address(0))
                ),
                upgradeOptions()
            )
        );
    }

    function _assumptions(address _user, address _provider)
        internal
        assumeNonZeroAddress(_user)
        assumeNonZeroAddress(_provider)
        assumeNotEqualAddress(_user, _provider)
        assumeNotEqualAddress(_user, address(market))
        assumeNotEqualAddress(_provider, address(market))
    {}

    function test_JobSettle_OnlyUSDC(address _user, address _provider, string memory _metadata) public {
        _assumptions(_user, _provider);

        uint256 _initialBalance = Utils.usdc(50);
        usdc.mint(_user, _initialBalance);
        uint256 _noticePeriodCost = Utils.calcAmountToPay(Utils.JOB_RATE, Utils.NOTICE_PERIOD);

        vm.startPrank(_user);
        usdc.approve(address(market), _initialBalance);
        market.jobOpen(_metadata, _provider, Utils.JOB_RATE, _initialBalance);
        vm.stopPrank();

        skip(2000);
        uint256 _settleAmount = Utils.usdc(40);
        vm.expectEmit();
        emit Market.MarketTokenSettled(jobId, block.timestamp, _provider, _settleAmount);
        vm.expectEmit();
        emit Market.MarketJobSettled(jobId, block.timestamp, _settleAmount, _provider);
        market.jobSettle(jobId);

        assertEq(
            market,
            jobId,
            Market.Job(
                _metadata,
                _user,
                _provider,
                Utils.JOB_RATE,
                _initialBalance - _noticePeriodCost - _settleAmount,
                block.timestamp,
                Utils.JOB_RATE
            )
        );

        assertEq(market.creditBalances(jobId), 0);

        assertEq(usdc.balanceOf(_user), 0);
        assertEq(usdc.balanceOf(address(market)), _initialBalance - _noticePeriodCost - _settleAmount);
        assertEq(usdc.balanceOf(_provider), _noticePeriodCost + _settleAmount);
    }

    function test_JobSettle_NotEnoughBalance(address _user, address _provider, string memory _metadata) public {
        _assumptions(_user, _provider);

        uint256 _initialBalance = Utils.usdc(50);
        uint256 _initialTokenBalance = Utils.usdc(50);
        usdc.mint(_user, _initialTokenBalance);
        uint256 _noticePeriodCost = Utils.calcAmountToPay(Utils.JOB_RATE, Utils.NOTICE_PERIOD);

        vm.startPrank(_user);
        usdc.approve(address(market), _initialTokenBalance);
        market.jobOpen(_metadata, _provider, Utils.JOB_RATE, _initialBalance);
        vm.stopPrank();

        skip(3000);
        uint256 _settleAmount = Utils.usdc(50) - _noticePeriodCost;
        uint256 _tokenSettleAmount = _initialTokenBalance - _noticePeriodCost;
        vm.expectEmit();
        emit Market.MarketTokenSettled(jobId, block.timestamp, _provider, _tokenSettleAmount);
        vm.expectEmit();
        emit Market.MarketJobSettled(jobId, block.timestamp, _settleAmount, _provider);
        market.jobSettle(jobId);

        assertEq(
            market,
            jobId,
            Market.Job(
                _metadata,
                _user,
                _provider,
                Utils.JOB_RATE,
                _initialBalance - _noticePeriodCost - _settleAmount,
                block.timestamp,
                Utils.JOB_RATE
            )
        );

        assertEq(market.creditBalances(jobId), 0);

        assertEq(usdc.balanceOf(_user), 0);
        assertEq(usdc.balanceOf(address(market)), _initialBalance - _noticePeriodCost - _settleAmount);
        assertEq(usdc.balanceOf(_provider), _noticePeriodCost + _settleAmount);
    }
}

contract MarketTestJobDeposit is MarketTest {
    Market market;
    ERC20Mock usdc;
    CreditMock credit;
    uint256 creditTokenBalance;
    uint64 jobId;
    address user;
    address provider;
    uint256 initialBalance;
    uint256 initialTokenBalance;
    uint256 initialCreditBalance;
    uint256 noticePeriodCost;

    function setUp() public {
        usdc = new ERC20Mock("Circle USD", "USDC");
        credit = new CreditMock(usdc);
        creditTokenBalance = Utils.usdc(1000);
        usdc.mint(address(credit), creditTokenBalance);
        jobId = uint64(vm.randomUint(0, 10000));
        market = Market(
            Upgrades.deployUUPSProxy(
                "Market.sol",
                abi.encodeCall(
                    Market.initialize, (vm.randomAddress(), jobId, Utils.NOTICE_PERIOD, address(usdc), address(credit))
                ),
                upgradeOptions()
            )
        );
        do {
            user = vm.randomAddress();
        } while (user == address(0) || user == address(market) || user == address(credit));
        do {
            provider = vm.randomAddress();
        } while (
            provider == address(0) || provider == address(market) || provider == address(credit) || provider == user
        );
        initialBalance = Utils.usdc(50);
        initialTokenBalance = Utils.usdc(20);
        initialCreditBalance = Utils.usdc(30);
        usdc.mint(user, initialTokenBalance);
        credit.mint(user, initialCreditBalance);
        noticePeriodCost = Utils.calcAmountToPay(Utils.JOB_RATE, Utils.NOTICE_PERIOD);

        vm.startPrank(user);
        usdc.approve(address(market), initialTokenBalance);
        credit.approve(address(market), initialCreditBalance);
        market.jobOpen("abcd", provider, Utils.JOB_RATE, initialBalance);
        vm.stopPrank();
    }

    function test_JobDeposit_OnlyUSDC() public {
        uint256 _depositAmount = Utils.usdc(40);
        usdc.mint(user, _depositAmount);

        vm.startPrank(user);
        usdc.approve(address(market), _depositAmount);
        vm.expectEmit();
        emit Market.MarketTokenDeposited(jobId, block.timestamp, user, _depositAmount);
        vm.expectEmit();
        emit Market.MarketJobDeposited(jobId, block.timestamp, _depositAmount, user);
        market.jobDeposit(jobId, _depositAmount);
        vm.stopPrank();

        assertEq(
            market,
            jobId,
            Market.Job(
                "abcd",
                user,
                provider,
                Utils.JOB_RATE,
                initialBalance - noticePeriodCost + _depositAmount,
                block.timestamp,
                Utils.JOB_RATE
            )
        );

        assertEq(market.creditBalances(jobId), initialCreditBalance - noticePeriodCost);

        assertEq(usdc.balanceOf(user), 0);
        assertEq(usdc.balanceOf(address(market)), initialTokenBalance + _depositAmount);
        assertEq(usdc.balanceOf(provider), noticePeriodCost);
        assertEq(usdc.balanceOf(address(credit)), creditTokenBalance - noticePeriodCost);
        assertEq(credit.balanceOf(user), 0);
        assertEq(credit.balanceOf(address(market)), initialCreditBalance - noticePeriodCost);
        assertEq(credit.balanceOf(provider), 0);
    }

    function test_JobDeposit_OnlyCredit() public {
        uint256 _depositAmount = Utils.usdc(40);
        credit.mint(user, _depositAmount);

        vm.startPrank(user);
        credit.approve(address(market), _depositAmount);
        vm.expectEmit();
        emit Market.MarketCreditTokenDeposited(jobId, block.timestamp, user, _depositAmount);
        vm.expectEmit();
        emit Market.MarketJobDeposited(jobId, block.timestamp, _depositAmount, user);
        market.jobDeposit(jobId, _depositAmount);
        vm.stopPrank();

        assertEq(
            market,
            jobId,
            Market.Job(
                "abcd",
                user,
                provider,
                Utils.JOB_RATE,
                initialBalance - noticePeriodCost + _depositAmount,
                block.timestamp,
                Utils.JOB_RATE
            )
        );

        assertEq(market.creditBalances(jobId), initialCreditBalance - noticePeriodCost + _depositAmount);

        assertEq(usdc.balanceOf(user), 0);
        assertEq(usdc.balanceOf(address(market)), initialTokenBalance);
        assertEq(usdc.balanceOf(provider), noticePeriodCost);
        assertEq(usdc.balanceOf(address(credit)), creditTokenBalance - noticePeriodCost);
        assertEq(credit.balanceOf(user), 0);
        assertEq(credit.balanceOf(address(market)), initialCreditBalance - noticePeriodCost + _depositAmount);
        assertEq(credit.balanceOf(provider), 0);
    }

    function test_JobDeposit_UsdcAndCredit() public {
        uint256 _depositAmount = Utils.usdc(40);
        uint256 _tokenDepositAmount = Utils.usdc(10);
        uint256 _creditDepositAmount = Utils.usdc(30);
        usdc.mint(user, _tokenDepositAmount);
        credit.mint(user, _creditDepositAmount);

        vm.startPrank(user);
        usdc.approve(address(market), _tokenDepositAmount);
        credit.approve(address(market), _creditDepositAmount);
        vm.expectEmit();
        emit Market.MarketCreditTokenDeposited(jobId, block.timestamp, user, _creditDepositAmount);
        vm.expectEmit();
        emit Market.MarketTokenDeposited(jobId, block.timestamp, user, _tokenDepositAmount);
        vm.expectEmit();
        emit Market.MarketJobDeposited(jobId, block.timestamp, _depositAmount, user);
        market.jobDeposit(jobId, _depositAmount);
        vm.stopPrank();

        assertEq(
            market,
            jobId,
            Market.Job(
                "abcd",
                user,
                provider,
                Utils.JOB_RATE,
                initialBalance - noticePeriodCost + _depositAmount,
                block.timestamp,
                Utils.JOB_RATE
            )
        );

        assertEq(market.creditBalances(jobId), initialCreditBalance - noticePeriodCost + _creditDepositAmount);

        assertEq(usdc.balanceOf(user), 0);
        assertEq(usdc.balanceOf(address(market)), initialTokenBalance + _tokenDepositAmount);
        assertEq(usdc.balanceOf(provider), noticePeriodCost);
        assertEq(usdc.balanceOf(address(credit)), creditTokenBalance - noticePeriodCost);
        assertEq(credit.balanceOf(user), 0);
        assertEq(credit.balanceOf(address(market)), initialCreditBalance - noticePeriodCost + _creditDepositAmount);
        assertEq(credit.balanceOf(provider), 0);
    }

    function test_JobDeposit_NonExistent() public {
        uint256 _depositAmount = Utils.usdc(40);
        uint256 _tokenDepositAmount = Utils.usdc(10);
        uint256 _creditDepositAmount = Utils.usdc(30);
        usdc.mint(user, _tokenDepositAmount);
        credit.mint(user, _creditDepositAmount);

        vm.startPrank(user);
        usdc.approve(address(market), _tokenDepositAmount);
        credit.approve(address(market), _creditDepositAmount);
        vm.expectRevert(Market.MarketJobNotFound.selector);
        market.jobDeposit(jobId + 1, _depositAmount);
        vm.stopPrank();
    }

    function test_JobDeposit_Inactive() public {
        uint256 _depositAmount = Utils.usdc(40);
        uint256 _tokenDepositAmount = Utils.usdc(10);
        uint256 _creditDepositAmount = Utils.usdc(30);
        usdc.mint(user, _tokenDepositAmount);
        credit.mint(user, _creditDepositAmount);

        vm.startPrank(user);
        skip(3000);
        usdc.approve(address(market), _tokenDepositAmount);
        credit.approve(address(market), _creditDepositAmount);
        vm.expectRevert(Market.MarketJobInactive.selector);
        market.jobDeposit(jobId, _depositAmount);
        vm.stopPrank();
    }
}

contract MarketTestJobDepositNoCredit is MarketTest {
    Market market;
    ERC20Mock usdc;
    uint64 jobId;
    address user;
    address provider;
    uint256 initialBalance;
    uint256 noticePeriodCost;

    function setUp() public {
        usdc = new ERC20Mock("Circle USD", "USDC");
        jobId = uint64(vm.randomUint(0, 10000));
        market = Market(
            Upgrades.deployUUPSProxy(
                "Market.sol",
                abi.encodeCall(
                    Market.initialize, (vm.randomAddress(), jobId, Utils.NOTICE_PERIOD, address(usdc), address(0))
                ),
                upgradeOptions()
            )
        );
        do {
            user = vm.randomAddress();
        } while (user == address(0) || user == address(market));
        do {
            provider = vm.randomAddress();
        } while (provider == address(0) || provider == address(market) || provider == user);
        initialBalance = Utils.usdc(50);
        usdc.mint(user, initialBalance);
        noticePeriodCost = Utils.calcAmountToPay(Utils.JOB_RATE, Utils.NOTICE_PERIOD);

        vm.startPrank(user);
        usdc.approve(address(market), initialBalance);
        market.jobOpen("abcd", provider, Utils.JOB_RATE, initialBalance);
        vm.stopPrank();
    }

    function test_JobDeposit_OnlyUSDC() public {
        uint256 _depositAmount = Utils.usdc(40);
        usdc.mint(user, _depositAmount);

        vm.startPrank(user);
        usdc.approve(address(market), _depositAmount);
        vm.expectEmit();
        emit Market.MarketTokenDeposited(jobId, block.timestamp, user, _depositAmount);
        vm.expectEmit();
        emit Market.MarketJobDeposited(jobId, block.timestamp, _depositAmount, user);
        market.jobDeposit(jobId, _depositAmount);
        vm.stopPrank();

        assertEq(
            market,
            jobId,
            Market.Job(
                "abcd",
                user,
                provider,
                Utils.JOB_RATE,
                initialBalance - noticePeriodCost + _depositAmount,
                block.timestamp,
                Utils.JOB_RATE
            )
        );

        assertEq(market.creditBalances(jobId), 0);

        assertEq(usdc.balanceOf(user), 0);
        assertEq(usdc.balanceOf(address(market)), initialBalance - noticePeriodCost + _depositAmount);
        assertEq(usdc.balanceOf(provider), noticePeriodCost);
    }

    function test_JobDeposit_NonExistent() public {
        uint256 _depositAmount = Utils.usdc(40);
        usdc.mint(user, _depositAmount);

        vm.startPrank(user);
        usdc.approve(address(market), _depositAmount);
        vm.expectRevert(Market.MarketJobNotFound.selector);
        market.jobDeposit(jobId + 1, _depositAmount);
        vm.stopPrank();
    }

    function test_JobDeposit_Inactive() public {
        uint256 _depositAmount = Utils.usdc(40);
        usdc.mint(user, _depositAmount);

        vm.startPrank(user);
        skip(3000);
        usdc.approve(address(market), _depositAmount);
        vm.expectRevert(Market.MarketJobInactive.selector);
        market.jobDeposit(jobId, _depositAmount);
        vm.stopPrank();
    }
}

contract MarketV2 is Market {
    function version() external pure returns (uint256) {
        return 2;
    }
}

abstract contract MarketTestBase is Test {
    Market market;
    ERC20Mock token;
    CreditMock creditToken;

    address admin = address(1);
    address user = address(2);
    address provider = address(3);
    address user2 = address(4);
    address admin2 = address(5);

    uint256 constant ONE_MINUTE = 60;
    uint256 constant TWO_MINUTES = 60 * 2;
    uint256 constant FIVE_MINUTES = 60 * 5;
    uint256 constant NOTICE_PERIOD = FIVE_MINUTES;

    uint256 constant SIGNER1_INITIAL_FUND = 1000 * 10 ** 6;
    uint256 constant SIGNER2_INITIAL_FUND = 1000 * 10 ** 6;
    uint256 constant JOB_RATE = 1 * 10 ** 16; // 0.01 USDC/s

    uint64 initialJobIndex;
    uint256 jobOpenedTimestamp;
    uint256 initialTimestamp;

    event MarketProviderAdded(address indexed provider, string cp);
    event MarketProviderRemoved(address indexed provider);
    event MarketProviderUpdated(address indexed provider, string oldCp, string newCp);
    event MarketTokenUpdated(address indexed oldToken, address indexed newToken);
    event MarketCreditTokenUpdated(address indexed oldCreditToken, address indexed newCreditToken);
    event MarketNoticePeriodUpdated(uint256 noticePeriod);
    event MarketJobOpened(
        uint64 indexed jobId, string metadata, address indexed owner, address indexed provider, uint256 timestamp
    );
    event MarketJobSettled(uint64 indexed jobId, uint256 lastSettled);
    event MarketJobClosed(uint64 indexed jobId, uint256 timestamp);
    event MarketJobDeposited(uint64 indexed jobId, address indexed token, address indexed from, uint256 amount);
    event MarketJobWithdrawn(uint64 indexed jobId, address indexed token, address indexed to, uint256 amount);
    event MarketJobSettlementWithdrawn(
        uint64 indexed jobId, address indexed token, address indexed provider, uint256 amount
    );
    event MarketJobRateRevised(uint64 indexed jobId, uint256 newRate);
    event MarketJobMetadataUpdated(uint64 indexed jobId, string metadata);

    function setUp() public virtual {
        token = new ERC20Mock("Pond", "POND");
        token.mint(user, SIGNER1_INITIAL_FUND);
        token.mint(user2, SIGNER2_INITIAL_FUND);

        creditToken = new CreditMock(token);
        token.mint(address(creditToken), 1000000 * 10 ** 6);

        address proxy = Upgrades.deployUUPSProxy(
            "Market.sol",
            abi.encodeCall(Market.initialize, (admin, 1234, FIVE_MINUTES, address(token), address(creditToken))),
            upgradeOptions()
        );
        market = Market(proxy);

        vm.startPrank(admin);
        market.updateNoticePeriod(FIVE_MINUTES);
        vm.stopPrank();

        vm.warp(1000000);
        initialTimestamp = block.timestamp;

        creditToken.mint(admin, 1000 * 10 ** 6);
        vm.prank(admin);
        creditToken.transfer(user, 1000 * 10 ** 6);

        initialJobIndex = market.jobIndex();
    }

    function calcNoticePeriodCost(uint256 rate) internal pure returns (uint256) {
        return calcAmountToPay(rate, NOTICE_PERIOD);
    }

    function calcAmountToPay(uint256 rate, uint256 duration) internal pure returns (uint256) {
        uint256 decimals = 10 ** 12;
        return (rate * duration + decimals - 1) / decimals;
    }

    function usdc(uint256 amount) internal pure returns (uint256) {
        return amount * 10 ** 6;
    }
}

contract MarketTestJobOpen is MarketTestBase {
    function test_JobOpen_with_USDC_only() public {
        uint256 initialBalance = usdc(50);
        uint256 noticePeriodCost = calcNoticePeriodCost(JOB_RATE_1);

        vm.startPrank(user);
        token.approve(address(market), initialBalance);

        vm.expectEmit(true, false, false, true);
        emit MarketJobOpened(initialJobIndex, "some metadata", user, provider, block.timestamp);

        market.jobOpen("some metadata", provider, JOB_RATE_1, initialBalance);
        vm.stopPrank();

        (
            string memory metadata,
            address owner_,
            address provider_,
            uint256 rate,
            uint256 balance,
            uint256 lastSettled,
            uint256 maxRate
        ) = market.jobs(initialJobIndex);
        assertEq(metadata, "some metadata");
        assertEq(owner_, user);
        assertEq(provider_, provider);
        assertEq(rate, JOB_RATE_1);
        assertEq(balance, initialBalance - noticePeriodCost);
        assertEq(lastSettled, block.timestamp);
        assertEq(maxRate, JOB_RATE_1);

        assertEq(token.balanceOf(user), SIGNER1_INITIAL_FUND - initialBalance);
        assertEq(token.balanceOf(address(market)), initialBalance - noticePeriodCost);
    }

    function test_JobOpen_increments_job_index_correctly() public {
        uint256 initialBalance = usdc(10);
        uint64 startingJobIndex = market.jobIndex();

        vm.startPrank(user);
        token.approve(address(market), initialBalance * 3);
        market.jobOpen("some metadata", provider, JOB_RATE_1, initialBalance);

        (string memory metadata,,,,,,) = market.jobs(startingJobIndex);
        assertEq(metadata, "some metadata");

        market.jobOpen("some metadata2", provider, JOB_RATE_1, initialBalance);
        uint64 secondJobId = startingJobIndex + 1;
        (metadata,,,,,,) = market.jobs(secondJobId);
        assertEq(metadata, "some metadata2");

        market.jobOpen("some metadata3", provider, JOB_RATE_1, initialBalance);
        uint64 thirdJobId = startingJobIndex + 2;
        (metadata,,,,,,) = market.jobs(thirdJobId);
        assertEq(metadata, "some metadata3");
        vm.stopPrank();
    }

    function test_JobOpen_with_Credit_only() public {
        uint256 initialBalance = usdc(50);
        uint256 noticePeriodCost = calcNoticePeriodCost(JOB_RATE_1);

        vm.startPrank(user);
        creditToken.approve(address(market), initialBalance);
        market.jobOpen("some metadata", provider, JOB_RATE_1, initialBalance);
        vm.stopPrank();

        (
            string memory metadata,
            address owner_,
            address provider_,
            uint256 rate,
            uint256 balance,
            uint256 lastSettled,
        ) = market.jobs(initialJobIndex);
        assertEq(metadata, "some metadata");
        assertEq(owner_, user);
        assertEq(provider_, provider);
        assertEq(rate, JOB_RATE_1);
        assertEq(balance, initialBalance - noticePeriodCost);
        assertEq(lastSettled, block.timestamp);

        assertEq(market.jobCreditBalance(initialJobIndex), initialBalance - noticePeriodCost);
    }

    function test_JobOpen_with_USDC_and_Credit() public {
        uint256 totalBalance = usdc(50);
        uint256 creditBalance = usdc(10);
        uint256 noticePeriodCost = calcNoticePeriodCost(JOB_RATE_1);

        vm.startPrank(user);
        token.approve(address(market), totalBalance);
        creditToken.approve(address(market), creditBalance);
        market.jobOpen("some metadata", provider, JOB_RATE_1, totalBalance);
        vm.stopPrank();

        (string memory metadata, address owner_, address provider_, uint256 rate, uint256 balance,,) =
            market.jobs(initialJobIndex);
        assertEq(metadata, "some metadata");
        assertEq(owner_, user);
        assertEq(provider_, provider);
        assertEq(rate, JOB_RATE_1);
        assertEq(balance, totalBalance - noticePeriodCost);
        assertEq(market.jobCreditBalance(initialJobIndex), creditBalance - noticePeriodCost);
    }

    function test_JobOpen_reverts_without_enough_approved() public {
        vm.prank(user);
        vm.expectRevert(
            abi.encodeWithSignature(
                "ERC20InsufficientAllowance(address,uint256,uint256)", address(market), 0, usdc(150)
            )
        );
        market.jobOpen("some metadata", provider, JOB_RATE_1, usdc(150));
    }

    function test_JobOpen_reverts_without_enough_balance() public {
        vm.startPrank(user);
        token.approve(address(market), usdc(5000));
        vm.expectRevert(
            abi.encodeWithSignature(
                "ERC20InsufficientBalance(address,uint256,uint256)", user, token.balanceOf(user), usdc(5000)
            )
        );
        market.jobOpen("some metadata", provider, JOB_RATE_1, usdc(5000));
        vm.stopPrank();
    }
}

contract MarketTestJobSettle is MarketTestBase {
    function test_JobSettle_immediately() public {
        uint256 initialDeposit = usdc(50);
        uint256 initialBalance = initialDeposit - calcNoticePeriodCost(JOB_RATE_1);

        vm.startPrank(user);
        token.approve(address(market), initialDeposit);
        market.jobOpen("some metadata", provider, JOB_RATE_1, initialDeposit);

        market.jobSettle(initialJobIndex);
        vm.stopPrank();

        (,,,, uint256 balance, uint256 lastSettled,) = market.jobs(initialJobIndex);
        assertEq(balance, initialBalance);
        assertEq(lastSettled, block.timestamp);
    }

    function test_JobSettle_after_2_minutes() public {
        uint256 initialDeposit = usdc(50);
        uint256 initialBalance = initialDeposit - calcNoticePeriodCost(JOB_RATE_1);

        vm.startPrank(user);
        token.approve(address(market), initialDeposit);
        market.jobOpen("some metadata", provider, JOB_RATE_1, initialDeposit);
        uint256 openTimestamp = block.timestamp;
        vm.stopPrank();

        vm.warp(block.timestamp + TWO_MINUTES);

        vm.prank(user);
        vm.expectEmit(true, false, false, true);
        emit MarketJobSettled(initialJobIndex, block.timestamp);
        market.jobSettle(initialJobIndex);

        (,,,, uint256 balance, uint256 lastSettled,) = market.jobs(initialJobIndex);
        assertEq(lastSettled, openTimestamp + TWO_MINUTES);
        assertEq(balance, initialBalance - calcAmountToPay(JOB_RATE_1, TWO_MINUTES));
    }

    function test_JobSettle_InsufficientBalance() public {
        uint256 initialDeposit = calcNoticePeriodCost(JOB_RATE_1) + usdc(1); // very small balance

        vm.startPrank(user);
        token.approve(address(market), initialDeposit);
        market.jobOpen("some metadata", provider, JOB_RATE_1, initialDeposit);
        vm.stopPrank();

        // Wait long enough so that usage exceeds balance
        vm.warp(block.timestamp + TWO_MINUTES * 10);

        vm.prank(user);
        market.jobSettle(initialJobIndex);

        (,,,, uint256 balance, uint256 lastSettled,) = market.jobs(initialJobIndex);
        assertEq(balance, 0); // Balance should be completely drained
        assertEq(lastSettled, block.timestamp); // Should still settle what it could
    }
}

contract MarketTestJobDeposit is MarketTestBase {
    function test_JobDeposit_USDC() public {
        uint256 initialDeposit = usdc(50);
        uint256 additionalDeposit = usdc(25);

        vm.startPrank(user);
        token.approve(address(market), initialDeposit + additionalDeposit);
        market.jobOpen("some metadata", provider, JOB_RATE_1, initialDeposit);

        uint256 balanceBefore = token.balanceOf(address(market));

        vm.expectEmit(true, true, true, true);
        emit MarketJobDeposited(initialJobIndex, address(token), user, additionalDeposit);

        market.jobDeposit(initialJobIndex, additionalDeposit);
        vm.stopPrank();

        (,,,, uint256 balance,,) = market.jobs(initialJobIndex);
        assertEq(balance, initialDeposit - calcNoticePeriodCost(JOB_RATE_1) + additionalDeposit);
        assertEq(token.balanceOf(address(market)), balanceBefore + additionalDeposit);
    }
}

contract MarketTestJobWithdraw is MarketTestBase {
    function test_JobWithdraw_USDC() public {
        uint256 initialDeposit = usdc(50);
        uint256 withdrawAmount = usdc(10);

        vm.startPrank(user);
        token.approve(address(market), initialDeposit);
        market.jobOpen("some metadata", provider, JOB_RATE_1, initialDeposit);

        vm.expectEmit(true, true, true, true);
        emit MarketJobWithdrawn(initialJobIndex, address(token), user, withdrawAmount);

        market.jobWithdraw(initialJobIndex, withdrawAmount);
        vm.stopPrank();

        (,,,, uint256 balance,,) = market.jobs(initialJobIndex);
        assertEq(balance, initialDeposit - calcNoticePeriodCost(JOB_RATE_1) - withdrawAmount);
    }

    function test_JobWithdraw_Credit_Fallback() public {
        // Test withdrawing more than the USDC balance, forcing fallback to credit token
        uint256 usdcDeposit = usdc(10) + calcNoticePeriodCost(JOB_RATE_1);
        uint256 creditDeposit = usdc(40);

        vm.startPrank(user);
        token.approve(address(market), usdcDeposit + creditDeposit);
        creditToken.approve(address(market), creditDeposit);
        market.jobOpen("some metadata", provider, JOB_RATE_1, usdcDeposit + creditDeposit);

        // At this point, jobBalance = 50, jobTokenBalance = 10, jobCreditBalance = 40
        // Withdraw 20, which is > 10 (USDC portion). Should withdraw 10 USDC and 10 Credit

        market.jobWithdraw(initialJobIndex, usdc(20));
        vm.stopPrank();

        (,,,, uint256 balance,,) = market.jobs(initialJobIndex);
        assertEq(balance, usdc(30)); // 50 - 20
        assertEq(market.jobCreditBalance(initialJobIndex), usdc(30)); // 40 - 10
    }

    function test_JobWithdraw_ExceedsBalance() public {
        uint256 initialDeposit = usdc(50);

        vm.startPrank(user);
        token.approve(address(market), initialDeposit);
        market.jobOpen("some metadata", provider, JOB_RATE_1, initialDeposit);

        vm.expectRevert(Market.MarketWithdrawalAmountExceedsJobBalance.selector);
        market.jobWithdraw(initialJobIndex, usdc(100)); // Trying to withdraw more than exists
        vm.stopPrank();
    }
}

contract MarketTestJobReviseRate is MarketTestBase {
    function test_JobReviseRate_higher() public {
        uint256 initialDeposit = usdc(50);
        uint256 initialBalance = initialDeposit - calcNoticePeriodCost(JOB_RATE_1);
        uint256 higherRate = 2 * 10 ** 16;

        vm.startPrank(user);
        token.approve(address(market), initialDeposit);
        market.jobOpen("some metadata", provider, JOB_RATE_1, initialDeposit);

        vm.expectEmit(true, false, false, true);
        emit MarketJobRateRevised(initialJobIndex, higherRate);
        market.jobReviseRate(initialJobIndex, higherRate);
        vm.stopPrank();

        (,,, uint256 rate, uint256 balance,, uint256 maxRate) = market.jobs(initialJobIndex);
        assertEq(rate, higherRate);
        assertEq(maxRate, higherRate);
        assertEq(balance, initialBalance - calcNoticePeriodCost(higherRate - JOB_RATE_1));
    }

    function test_JobReviseRate_InsufficientFundsToSettle() public {
        uint256 initialDeposit = calcNoticePeriodCost(JOB_RATE_1) + usdc(1);
        uint256 higherRate = 2 * 10 ** 16;

        vm.startPrank(user);
        token.approve(address(market), initialDeposit);
        market.jobOpen("some metadata", provider, JOB_RATE_1, initialDeposit);

        // Warp time so that balance is exhausted
        vm.warp(block.timestamp + TWO_MINUTES * 10);

        vm.expectRevert(Market.MarketInsufficientFundsToSettleBeforeRevisingRate.selector);
        market.jobReviseRate(initialJobIndex, higherRate);
        vm.stopPrank();
    }
}

contract MarketTestJobClose is MarketTestBase {
    function test_JobClose() public {
        uint256 initialDeposit = usdc(50);

        vm.startPrank(user);
        token.approve(address(market), initialDeposit);
        market.jobOpen("some metadata", provider, JOB_RATE_1, initialDeposit);

        vm.expectEmit(true, false, false, true);
        emit MarketJobClosed(initialJobIndex, block.timestamp);

        market.jobClose(initialJobIndex);
        vm.stopPrank();

        (string memory metadata, address owner_,, uint256 rate, uint256 balance,,) = market.jobs(initialJobIndex);
        assertEq(metadata, "");
        assertEq(owner_, address(0));
        assertEq(rate, 0);
        assertEq(balance, 0);

        assertEq(token.balanceOf(user), SIGNER1_INITIAL_FUND - calcNoticePeriodCost(JOB_RATE_1));
    }
}

contract MarketTestJobMetadataUpdate is MarketTestBase {
    function test_JobMetadataUpdate() public {
        uint256 initialDeposit = usdc(50);

        vm.startPrank(user);
        token.approve(address(market), initialDeposit);
        market.jobOpen("some metadata", provider, JOB_RATE_1, initialDeposit);

        vm.expectEmit(true, false, false, true);
        emit MarketJobMetadataUpdated(initialJobIndex, "new metadata");
        market.jobMetadataUpdate(initialJobIndex, "new metadata");
        vm.stopPrank();

        (string memory metadata,,,,,,) = market.jobs(initialJobIndex);
        assertEq(metadata, "new metadata");
    }
}

contract MarketTestEmergencyWithdraw is MarketTestBase {
    function test_EmergencyWithdraw() public {
        bytes32 role = market.EMERGENCY_WITHDRAW_ROLE();
        vm.prank(admin);
        market.grantRole(role, admin2);

        uint256 deposit = usdc(50);
        vm.startPrank(user);
        creditToken.approve(address(market), deposit);
        market.jobOpen("some metadata", provider, JOB_RATE_1, deposit);
        vm.stopPrank();

        uint64[] memory jobs = new uint64[](1);
        jobs[0] = initialJobIndex;

        vm.prank(admin);
        market.emergencyWithdrawCredit(admin2, jobs);

        assertEq(market.jobCreditBalance(initialJobIndex), 0);
        assertGt(creditToken.balanceOf(admin2), 0);
    }
}

contract MarketTestAdminOperations is MarketTestBase {
    function test_UpdateToken() public {
        ERC20Mock newToken = new ERC20Mock("New", "NEW");

        vm.prank(admin);
        vm.expectEmit(true, true, false, false);
        emit MarketTokenUpdated(address(token), address(newToken));
        market.updateToken(address(newToken));

        assertEq(address(market.realToken()), address(newToken));
    }

    function test_UpdateToken_NonAdmin() public {
        ERC20Mock newToken = new ERC20Mock("New", "NEW");

        vm.prank(user);
        vm.expectRevert(Market.MarketOnlyAdmin.selector);
        market.updateToken(address(newToken));
    }

    function test_UpdateCreditToken() public {
        ERC20Mock newToken = new ERC20Mock("New", "NEW");

        vm.prank(admin);
        vm.expectEmit(true, true, false, false);
        emit MarketCreditTokenUpdated(address(creditToken), address(newToken));
        market.updateCreditToken(address(newToken));

        assertEq(address(market.creditToken()), address(newToken));
    }

    function test_UpdateCreditToken_NonAdmin() public {
        ERC20Mock newToken = new ERC20Mock("New", "NEW");

        vm.prank(user);
        vm.expectRevert(Market.MarketOnlyAdmin.selector);
        market.updateCreditToken(address(newToken));
    }

    function test_WithdrawCreditTokenNotSet() public {
        // Set creditToken to address(0) to trigger line 572
        vm.prank(admin);
        market.updateCreditToken(address(0));

        // Open job with usdc, which works fine
        uint256 deposit = usdc(50);
        vm.startPrank(user);
        token.approve(address(market), deposit);
        market.jobOpen("some metadata", provider, JOB_RATE_1, deposit);
        vm.stopPrank();

        // This doesn't trigger 572 because creditAmount = 0
        // We can't realistically force jobCreditBalance > 0 AND creditToken == 0 in a single transaction if it's disabled.
        // Wait! We can deposit credit, THEN update credit token to 0, THEN withdraw!

        vm.prank(admin);
        market.updateCreditToken(address(creditToken));

        uint256 creditDeposit = usdc(50);
        vm.startPrank(user);
        creditToken.approve(address(market), creditDeposit);
        market.jobOpen("meta", provider, JOB_RATE_1, creditDeposit);
        vm.stopPrank();

        uint64 job2Id = initialJobIndex + 1;

        vm.prank(admin);
        market.updateCreditToken(address(0));

        vm.startPrank(user);
        vm.expectRevert(Market.MarketCreditTokenNotSet.selector);
        market.jobWithdraw(job2Id, usdc(10));
        vm.stopPrank();
    }
}

contract MarketTestUpgrade is MarketTestBase {
    function test_SupportsInterface() public view {
        assertTrue(market.supportsInterface(type(ERC165Upgradeable).interfaceId));
    }

    function test_Upgrade_Admin() public {
        MarketV2 v2 = new MarketV2();

        vm.prank(admin);
        market.upgradeToAndCall(address(v2), "");

        assertEq(MarketV2(address(market)).version(), 2);
    }

    function test_Upgrade_NonAdmin() public {
        MarketV2 v2 = new MarketV2();

        vm.prank(user);
        vm.expectRevert(Market.MarketOnlyAdmin.selector);
        market.upgradeToAndCall(address(v2), "");
    }
}

contract MarketTestAdditionalBranches is MarketTestBase {
    function test_JobDeposit_RevertsInvalidAmount() public {
        uint256 deposit = usdc(50);
        vm.startPrank(user);
        token.approve(address(market), deposit);
        market.jobOpen("some metadata", provider, JOB_RATE_1, deposit);

        vm.expectRevert(Market.MarketInvalidAmount.selector);
        market.jobDeposit(initialJobIndex, 0);
        vm.stopPrank();
    }

    function test_JobDeposit_RevertsJobNotFound() public {
        vm.prank(user);
        vm.expectRevert(Market.MarketJobNotFound.selector);
        market.jobDeposit(999, usdc(10));
    }

    function test_JobWithdraw_RevertsInvalidAmount() public {
        uint256 deposit = usdc(50);
        vm.startPrank(user);
        token.approve(address(market), deposit);
        market.jobOpen("some metadata", provider, JOB_RATE_1, deposit);

        vm.expectRevert(Market.MarketInvalidAmount.selector);
        market.jobWithdraw(initialJobIndex, 0);
        vm.stopPrank();
    }

    function test_JobWithdraw_RevertsOnlyJobOwner() public {
        uint256 deposit = usdc(50);
        vm.startPrank(user);
        token.approve(address(market), deposit);
        market.jobOpen("some metadata", provider, JOB_RATE_1, deposit);
        vm.stopPrank();

        vm.prank(user2);
        vm.expectRevert(Market.MarketOnlyJobOwner.selector);
        market.jobWithdraw(initialJobIndex, usdc(10));
    }

    function test_JobReviseRate_RevertsInvalidRate() public {
        uint256 deposit = usdc(50);
        vm.startPrank(user);
        token.approve(address(market), deposit);
        market.jobOpen("some metadata", provider, JOB_RATE_1, deposit);

        vm.expectRevert(Market.MarketInvalidRate.selector);
        market.jobReviseRate(initialJobIndex, 0);
        vm.stopPrank();
    }

    function test_JobReviseRate_RevertsRateNotChanged() public {
        uint256 deposit = usdc(50);
        vm.startPrank(user);
        token.approve(address(market), deposit);
        market.jobOpen("some metadata", provider, JOB_RATE_1, deposit);

        vm.expectRevert(Market.MarketRateNotChanged.selector);
        market.jobReviseRate(initialJobIndex, JOB_RATE_1);
        vm.stopPrank();
    }

    function test_JobReviseRate_RevertsOnlyJobOwner() public {
        uint256 deposit = usdc(50);
        vm.startPrank(user);
        token.approve(address(market), deposit);
        market.jobOpen("some metadata", provider, JOB_RATE_1, deposit);
        vm.stopPrank();

        vm.prank(user2);
        vm.expectRevert(Market.MarketOnlyJobOwner.selector);
        market.jobReviseRate(initialJobIndex, 2 * 10 ** 16);
    }

    function test_JobMetadataUpdate_RevertsNotChanged() public {
        uint256 initialDeposit = usdc(50);
        vm.startPrank(user);
        token.approve(address(market), initialDeposit);
        market.jobOpen("some metadata", provider, JOB_RATE_1, initialDeposit);

        vm.expectRevert(Market.MarketMetadataNotChanged.selector);
        market.jobMetadataUpdate(initialJobIndex, "some metadata");
        vm.stopPrank();
    }

    function test_JobMetadataUpdate_RevertsOnlyJobOwner() public {
        uint256 deposit = usdc(50);
        vm.startPrank(user);
        token.approve(address(market), deposit);
        market.jobOpen("some metadata", provider, JOB_RATE_1, deposit);
        vm.stopPrank();

        vm.prank(user2);
        vm.expectRevert(Market.MarketOnlyJobOwner.selector);
        market.jobMetadataUpdate(initialJobIndex, "new metadata");
    }

    function test_EmergencyWithdraw_RevertsOnlyEmergencyWithdrawRole() public {
        uint64[] memory jobs = new uint64[](1);
        jobs[0] = initialJobIndex;

        vm.prank(admin);
        vm.expectRevert(Market.MarketOnlyEmergencyWithdrawRole.selector);
        market.emergencyWithdrawCredit(user, jobs);
    }

    function test_JobClose_RevertsOnlyJobOwner() public {
        uint256 deposit = usdc(50);
        vm.startPrank(user);
        token.approve(address(market), deposit);
        market.jobOpen("some metadata", provider, JOB_RATE_1, deposit);
        vm.stopPrank();

        vm.prank(user2);
        vm.expectRevert(Market.MarketOnlyJobOwner.selector);
        market.jobClose(initialJobIndex);
    }

    function test_JobSettle_RevertsJobNotFound() public {
        vm.prank(user);
        vm.expectRevert(Market.MarketJobNotFound.selector);
        market.jobSettle(999);
    }
}
