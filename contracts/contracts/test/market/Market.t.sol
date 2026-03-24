// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test} from "../Test.sol";
import {Erc165Test} from "../Erc165Test.sol";
import {IERC165} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";
import {IAccessControl} from "@openzeppelin/contracts/access/IAccessControl.sol";
import {RbacAdminTest} from "../RbacTest.sol";
import {Initializable} from "@openzeppelin/contracts/proxy/utils/Initializable.sol";
import {Upgrades} from "openzeppelin-foundry-upgrades/Upgrades.sol";
import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {Market} from "../../src/market/Market.sol";
import {ICredit} from "../../src/token/ICredit.sol";
import {IERC20Errors} from "@openzeppelin/contracts/interfaces/draft-IERC6093.sol";

contract ERC20Mock is ERC20 {
    constructor(string memory name, string memory symbol) ERC20(name, symbol) {}

    function mint(address account, uint64 amount) public {
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
    uint64 public constant NOTICE_PERIOD = 300;
    uint64 public constant JOB_RATE = 2 * 10 ** 10; // 0.02 USDC/s

    function calcAmountToPay(uint64 rate, uint64 duration) internal pure returns (uint64) {
        uint64 decimals = 10 ** 6;
        return (rate * duration + decimals - 1) / decimals;
    }

    function usdc(uint64 amount) internal pure returns (uint64) {
        return amount * 10 ** 6;
    }
}

abstract contract MarketTest is Test {
    function assertEq(Market _market, uint64 _jobId, Market.Job memory _job) internal {
        (
            string memory _jobMetadata,
            address _jobOwner,
            address _jobProvider,
            uint64 _jobRate,
            uint64 _jobBalance,
            uint64 _jobLastSettled,
            uint64 _jobMaxRate
        ) = _market.jobs(_jobId);
        assertEq(_jobMetadata, _job.metadata);
        assertEq(_jobOwner, _job.owner);
        assertEq(_jobProvider, _job.provider);
        assertEq(_jobRate, _job.rate);
        assertEq(_jobBalance, _job.balance);
        assertEq(_jobLastSettled, _job.lastSettled);
        assertEq(_jobMaxRate, _job.maxRate);
    }

    function _now() internal view returns (uint64) {
        return uint64(block.timestamp);
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

    function test_UpdateNoticePeriod_Admin(uint64 _newNoticePeriod) public {
        vm.expectEmit();
        emit Market.MarketNoticePeriodUpdated(Utils.NOTICE_PERIOD, _newNoticePeriod);
        vm.prank(admin);
        market.updateNoticePeriod(_newNoticePeriod);

        assertEq(market.noticePeriod(), _newNoticePeriod);
    }

    function test_UpdateNoticePeriod_NonAdmin(uint64 _newNoticePeriod) public {
        vm.expectRevert(Market.MarketOnlyAdmin.selector);
        market.updateNoticePeriod(_newNoticePeriod);
    }
}

contract MarketTestUpdateToken is Test {
    Market market;
    address admin;
    address initialToken;

    function setUp() public {
        admin = vm.randomAddress();
        initialToken = vm.randomAddress();
        market = Market(
            Upgrades.deployUUPSProxy(
                "Market.sol",
                abi.encodeCall(
                    Market.initialize,
                    (admin, uint64(vm.randomUint()), Utils.NOTICE_PERIOD, initialToken, vm.randomAddress())
                ),
                upgradeOptions()
            )
        );
    }

    function test_UpdateToken_Admin(address _newToken) public {
        vm.expectEmit();
        emit Market.MarketTokenUpdated(initialToken, _newToken);
        vm.prank(admin);
        market.updateToken(_newToken);

        assertEq(address(market.token()), _newToken);
    }

    function test_UpdateToken_NonAdmin(address _newToken) public {
        vm.expectRevert(Market.MarketOnlyAdmin.selector);
        market.updateToken(_newToken);
    }
}

contract MarketTestUpdateCreditToken is Test {
    Market market;
    address admin;
    address initialCreditToken;

    function setUp() public {
        admin = vm.randomAddress();
        initialCreditToken = vm.randomAddress();
        market = Market(
            Upgrades.deployUUPSProxy(
                "Market.sol",
                abi.encodeCall(
                    Market.initialize,
                    (admin, uint64(vm.randomUint()), Utils.NOTICE_PERIOD, vm.randomAddress(), initialCreditToken)
                ),
                upgradeOptions()
            )
        );
    }

    function test_UpdateCreditToken_Admin(address _newCreditToken) public {
        vm.expectEmit();
        emit Market.MarketCreditTokenUpdated(initialCreditToken, _newCreditToken);
        vm.prank(admin);
        market.updateCreditToken(_newCreditToken);

        assertEq(address(market.creditToken()), _newCreditToken);
    }

    function test_UpdateCreditToken_NonAdmin(address _newCreditToken) public {
        vm.expectRevert(Market.MarketOnlyAdmin.selector);
        market.updateCreditToken(_newCreditToken);
    }
}

contract MarketTestJobOpen is MarketTest {
    Market market;
    ERC20Mock usdc;
    CreditMock credit;
    uint64 creditTokenBalance;
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

        uint64 _initialBalance = Utils.usdc(50);
        usdc.mint(_user, _initialBalance);
        uint64 _noticePeriodCost = Utils.calcAmountToPay(Utils.JOB_RATE, Utils.NOTICE_PERIOD);

        vm.startPrank(_user);
        usdc.approve(address(market), _initialBalance);
        vm.expectEmit();
        emit Market.MarketJobOpened(jobId, _now(), _metadata, _user, _provider);
        vm.expectEmit();
        emit Market.MarketTokenDeposited(jobId, _now(), _user, _initialBalance);
        vm.expectEmit();
        emit Market.MarketJobDeposited(jobId, _now(), _initialBalance, _user);
        vm.expectEmit();
        emit Market.MarketTokenSettled(jobId, _now(), _provider, _noticePeriodCost);
        vm.expectEmit();
        emit Market.MarketJobSettled(jobId, _now(), _noticePeriodCost, _provider);
        vm.expectEmit();
        emit Market.MarketJobRateRevised(jobId, _now(), Utils.JOB_RATE);
        market.jobOpen(_metadata, _provider, Utils.JOB_RATE, _initialBalance);
        vm.stopPrank();

        assertEq(
            market,
            jobId,
            Market.Job(
                _metadata, _user, _provider, Utils.JOB_RATE, _initialBalance - _noticePeriodCost, _now(), Utils.JOB_RATE
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

        uint64 _initialBalance = Utils.usdc(50);
        credit.mint(_user, _initialBalance);
        uint64 _noticePeriodCost = Utils.calcAmountToPay(Utils.JOB_RATE, Utils.NOTICE_PERIOD);

        vm.startPrank(_user);
        credit.approve(address(market), _initialBalance);
        vm.expectEmit();
        emit Market.MarketJobOpened(jobId, _now(), _metadata, _user, _provider);
        vm.expectEmit();
        emit Market.MarketCreditTokenDeposited(jobId, _now(), _user, _initialBalance);
        vm.expectEmit();
        emit Market.MarketJobDeposited(jobId, _now(), _initialBalance, _user);
        vm.expectEmit();
        emit Market.MarketCreditTokenSettled(jobId, _now(), _provider, _noticePeriodCost);
        vm.expectEmit();
        emit Market.MarketJobSettled(jobId, _now(), _noticePeriodCost, _provider);
        vm.expectEmit();
        emit Market.MarketJobRateRevised(jobId, _now(), Utils.JOB_RATE);
        market.jobOpen(_metadata, _provider, Utils.JOB_RATE, _initialBalance);
        vm.stopPrank();

        assertEq(
            market,
            jobId,
            Market.Job(
                _metadata, _user, _provider, Utils.JOB_RATE, _initialBalance - _noticePeriodCost, _now(), Utils.JOB_RATE
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

        uint64 _initialBalance = Utils.usdc(50);
        uint64 _initialTokenBalance = Utils.usdc(20);
        uint64 _initialCreditBalance = Utils.usdc(30);
        usdc.mint(_user, _initialTokenBalance);
        credit.mint(_user, _initialCreditBalance);
        uint64 _noticePeriodCost = Utils.calcAmountToPay(Utils.JOB_RATE, Utils.NOTICE_PERIOD);

        vm.startPrank(_user);
        usdc.approve(address(market), _initialTokenBalance);
        credit.approve(address(market), _initialCreditBalance);
        vm.expectEmit();
        emit Market.MarketJobOpened(jobId, _now(), _metadata, _user, _provider);
        vm.expectEmit();
        emit Market.MarketCreditTokenDeposited(jobId, _now(), _user, _initialCreditBalance);
        emit Market.MarketTokenDeposited(jobId, _now(), _user, _initialTokenBalance);
        vm.expectEmit();
        emit Market.MarketJobDeposited(jobId, _now(), _initialBalance, _user);
        vm.expectEmit();
        emit Market.MarketCreditTokenSettled(jobId, _now(), _provider, _noticePeriodCost);
        vm.expectEmit();
        emit Market.MarketJobSettled(jobId, _now(), _noticePeriodCost, _provider);
        vm.expectEmit();
        emit Market.MarketJobRateRevised(jobId, _now(), Utils.JOB_RATE);
        market.jobOpen(_metadata, _provider, Utils.JOB_RATE, _initialBalance);
        vm.stopPrank();

        assertEq(
            market,
            jobId,
            Market.Job(
                _metadata, _user, _provider, Utils.JOB_RATE, _initialBalance - _noticePeriodCost, _now(), Utils.JOB_RATE
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

        uint64 _initialBalance = Utils.usdc(50);
        uint64 _initialTokenBalance = Utils.usdc(10);
        uint64 _initialCreditBalance = Utils.usdc(30);
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

        uint64 _initialBalance = Utils.usdc(50);
        uint64 _initialTokenBalance = Utils.usdc(20);
        uint64 _initialCreditBalance = Utils.usdc(20);
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

        uint64 _initialBalance = Utils.usdc(50);
        usdc.mint(_user, _initialBalance);
        uint64 _noticePeriodCost = Utils.calcAmountToPay(Utils.JOB_RATE, Utils.NOTICE_PERIOD);

        vm.startPrank(_user);
        usdc.approve(address(market), _initialBalance);
        vm.expectEmit();
        emit Market.MarketJobOpened(jobId, _now(), _metadata, _user, _provider);
        vm.expectEmit();
        emit Market.MarketTokenDeposited(jobId, _now(), _user, _initialBalance);
        vm.expectEmit();
        emit Market.MarketJobDeposited(jobId, _now(), _initialBalance, _user);
        vm.expectEmit();
        emit Market.MarketTokenSettled(jobId, _now(), _provider, _noticePeriodCost);
        vm.expectEmit();
        emit Market.MarketJobSettled(jobId, _now(), _noticePeriodCost, _provider);
        vm.expectEmit();
        emit Market.MarketJobRateRevised(jobId, _now(), Utils.JOB_RATE);
        market.jobOpen(_metadata, _provider, Utils.JOB_RATE, _initialBalance);
        vm.stopPrank();

        assertEq(
            market,
            jobId,
            Market.Job(
                _metadata, _user, _provider, Utils.JOB_RATE, _initialBalance - _noticePeriodCost, _now(), Utils.JOB_RATE
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

        uint64 _initialBalance = Utils.usdc(50);
        uint64 _initialTokenBalance = Utils.usdc(10);
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
    uint64 creditTokenBalance;
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

        uint64 _initialBalance = Utils.usdc(50);
        usdc.mint(_user, _initialBalance);
        uint64 _noticePeriodCost = Utils.calcAmountToPay(Utils.JOB_RATE, Utils.NOTICE_PERIOD);

        vm.startPrank(_user);
        usdc.approve(address(market), _initialBalance);
        market.jobOpen(_metadata, _provider, Utils.JOB_RATE, _initialBalance);
        vm.stopPrank();

        skip(2000);
        uint64 _settleAmount = Utils.usdc(40);
        vm.expectEmit();
        emit Market.MarketTokenSettled(jobId, _now(), _provider, _settleAmount);
        vm.expectEmit();
        emit Market.MarketJobSettled(jobId, _now(), _settleAmount, _provider);
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
                _now(),
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

        uint64 _initialBalance = Utils.usdc(50);
        credit.mint(_user, _initialBalance);
        uint64 _noticePeriodCost = Utils.calcAmountToPay(Utils.JOB_RATE, Utils.NOTICE_PERIOD);

        vm.startPrank(_user);
        credit.approve(address(market), _initialBalance);
        market.jobOpen(_metadata, _provider, Utils.JOB_RATE, _initialBalance);
        vm.stopPrank();

        skip(2000);
        uint64 _settleAmount = Utils.usdc(40);
        vm.expectEmit();
        emit Market.MarketCreditTokenSettled(jobId, _now(), _provider, _settleAmount);
        vm.expectEmit();
        emit Market.MarketJobSettled(jobId, _now(), _settleAmount, _provider);
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
                _now(),
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

        uint64 _initialBalance = Utils.usdc(50);
        uint64 _initialTokenBalance = Utils.usdc(20);
        uint64 _initialCreditBalance = Utils.usdc(30);
        usdc.mint(_user, _initialTokenBalance);
        credit.mint(_user, _initialCreditBalance);
        uint64 _noticePeriodCost = Utils.calcAmountToPay(Utils.JOB_RATE, Utils.NOTICE_PERIOD);

        vm.startPrank(_user);
        usdc.approve(address(market), _initialTokenBalance);
        credit.approve(address(market), _initialCreditBalance);
        market.jobOpen(_metadata, _provider, Utils.JOB_RATE, _initialBalance);
        vm.stopPrank();

        skip(2000);
        uint64 _settleAmount = Utils.usdc(40);
        uint64 _tokenSettleAmount = Utils.usdc(10) + _noticePeriodCost;
        uint64 _creditSettleAmount = Utils.usdc(30) - _noticePeriodCost;
        vm.expectEmit();
        emit Market.MarketCreditTokenSettled(jobId, _now(), _provider, _creditSettleAmount);
        vm.expectEmit();
        emit Market.MarketTokenSettled(jobId, _now(), _provider, _tokenSettleAmount);
        vm.expectEmit();
        emit Market.MarketJobSettled(jobId, _now(), _settleAmount, _provider);
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
                _now(),
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

        uint64 _initialBalance = Utils.usdc(50);
        uint64 _initialTokenBalance = Utils.usdc(20);
        uint64 _initialCreditBalance = Utils.usdc(30);
        usdc.mint(_user, _initialTokenBalance);
        credit.mint(_user, _initialCreditBalance);
        uint64 _noticePeriodCost = Utils.calcAmountToPay(Utils.JOB_RATE, Utils.NOTICE_PERIOD);

        vm.startPrank(_user);
        usdc.approve(address(market), _initialTokenBalance);
        credit.approve(address(market), _initialCreditBalance);
        market.jobOpen(_metadata, _provider, Utils.JOB_RATE, _initialBalance);
        vm.stopPrank();

        skip(3000);
        uint64 _settleAmount = Utils.usdc(50) - _noticePeriodCost;
        uint64 _tokenSettleAmount = _initialTokenBalance;
        uint64 _creditSettleAmount = _initialCreditBalance - _noticePeriodCost;
        vm.expectEmit();
        emit Market.MarketCreditTokenSettled(jobId, _now(), _provider, _creditSettleAmount);
        vm.expectEmit();
        emit Market.MarketTokenSettled(jobId, _now(), _provider, _tokenSettleAmount);
        vm.expectEmit();
        emit Market.MarketJobSettled(jobId, _now(), _settleAmount, _provider);
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
                _now(),
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

        uint64 _initialBalance = Utils.usdc(50);
        usdc.mint(_user, _initialBalance);
        uint64 _noticePeriodCost = Utils.calcAmountToPay(Utils.JOB_RATE, Utils.NOTICE_PERIOD);

        vm.startPrank(_user);
        usdc.approve(address(market), _initialBalance);
        market.jobOpen(_metadata, _provider, Utils.JOB_RATE, _initialBalance);
        vm.stopPrank();

        skip(2000);
        uint64 _settleAmount = Utils.usdc(40);
        vm.expectEmit();
        emit Market.MarketTokenSettled(jobId, _now(), _provider, _settleAmount);
        vm.expectEmit();
        emit Market.MarketJobSettled(jobId, _now(), _settleAmount, _provider);
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
                _now(),
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

        uint64 _initialBalance = Utils.usdc(50);
        uint64 _initialTokenBalance = Utils.usdc(50);
        usdc.mint(_user, _initialTokenBalance);
        uint64 _noticePeriodCost = Utils.calcAmountToPay(Utils.JOB_RATE, Utils.NOTICE_PERIOD);

        vm.startPrank(_user);
        usdc.approve(address(market), _initialTokenBalance);
        market.jobOpen(_metadata, _provider, Utils.JOB_RATE, _initialBalance);
        vm.stopPrank();

        skip(3000);
        uint64 _settleAmount = Utils.usdc(50) - _noticePeriodCost;
        uint64 _tokenSettleAmount = _initialTokenBalance - _noticePeriodCost;
        vm.expectEmit();
        emit Market.MarketTokenSettled(jobId, _now(), _provider, _tokenSettleAmount);
        vm.expectEmit();
        emit Market.MarketJobSettled(jobId, _now(), _settleAmount, _provider);
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
                _now(),
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
    uint64 creditTokenBalance;
    uint64 jobId;
    address user;
    address provider;
    uint64 initialBalance;
    uint64 initialTokenBalance;
    uint64 initialCreditBalance;
    uint64 noticePeriodCost;

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
        uint64 _depositAmount = Utils.usdc(40);
        usdc.mint(user, _depositAmount);

        vm.startPrank(user);
        usdc.approve(address(market), _depositAmount);
        vm.expectEmit();
        emit Market.MarketTokenDeposited(jobId, _now(), user, _depositAmount);
        vm.expectEmit();
        emit Market.MarketJobDeposited(jobId, _now(), _depositAmount, user);
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
                _now(),
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
        uint64 _depositAmount = Utils.usdc(40);
        credit.mint(user, _depositAmount);

        vm.startPrank(user);
        credit.approve(address(market), _depositAmount);
        vm.expectEmit();
        emit Market.MarketCreditTokenDeposited(jobId, _now(), user, _depositAmount);
        vm.expectEmit();
        emit Market.MarketJobDeposited(jobId, _now(), _depositAmount, user);
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
                _now(),
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
        uint64 _depositAmount = Utils.usdc(40);
        uint64 _tokenDepositAmount = Utils.usdc(10);
        uint64 _creditDepositAmount = Utils.usdc(30);
        usdc.mint(user, _tokenDepositAmount);
        credit.mint(user, _creditDepositAmount);

        vm.startPrank(user);
        usdc.approve(address(market), _tokenDepositAmount);
        credit.approve(address(market), _creditDepositAmount);
        vm.expectEmit();
        emit Market.MarketCreditTokenDeposited(jobId, _now(), user, _creditDepositAmount);
        vm.expectEmit();
        emit Market.MarketTokenDeposited(jobId, _now(), user, _tokenDepositAmount);
        vm.expectEmit();
        emit Market.MarketJobDeposited(jobId, _now(), _depositAmount, user);
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
                _now(),
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
        uint64 _depositAmount = Utils.usdc(40);
        uint64 _tokenDepositAmount = Utils.usdc(10);
        uint64 _creditDepositAmount = Utils.usdc(30);
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
        uint64 _depositAmount = Utils.usdc(40);
        uint64 _tokenDepositAmount = Utils.usdc(10);
        uint64 _creditDepositAmount = Utils.usdc(30);
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
    uint64 initialBalance;
    uint64 noticePeriodCost;

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
        uint64 _depositAmount = Utils.usdc(40);
        usdc.mint(user, _depositAmount);

        vm.startPrank(user);
        usdc.approve(address(market), _depositAmount);
        vm.expectEmit();
        emit Market.MarketTokenDeposited(jobId, _now(), user, _depositAmount);
        vm.expectEmit();
        emit Market.MarketJobDeposited(jobId, _now(), _depositAmount, user);
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
                _now(),
                Utils.JOB_RATE
            )
        );

        assertEq(market.creditBalances(jobId), 0);

        assertEq(usdc.balanceOf(user), 0);
        assertEq(usdc.balanceOf(address(market)), initialBalance - noticePeriodCost + _depositAmount);
        assertEq(usdc.balanceOf(provider), noticePeriodCost);
    }

    function test_JobDeposit_NonExistent() public {
        uint64 _depositAmount = Utils.usdc(40);
        usdc.mint(user, _depositAmount);

        vm.startPrank(user);
        usdc.approve(address(market), _depositAmount);
        vm.expectRevert(Market.MarketJobNotFound.selector);
        market.jobDeposit(jobId + 1, _depositAmount);
        vm.stopPrank();
    }

    function test_JobDeposit_Inactive() public {
        uint64 _depositAmount = Utils.usdc(40);
        usdc.mint(user, _depositAmount);

        vm.startPrank(user);
        skip(3000);
        usdc.approve(address(market), _depositAmount);
        vm.expectRevert(Market.MarketJobInactive.selector);
        market.jobDeposit(jobId, _depositAmount);
        vm.stopPrank();
    }
}

contract MarketTestJobWithdraw is MarketTest {
    Market market;
    ERC20Mock usdc;
    CreditMock credit;
    uint64 creditTokenBalance;
    uint64 jobId;
    address user;
    address provider;
    uint64 initialBalance;
    uint64 initialTokenBalance;
    uint64 initialCreditBalance;
    uint64 noticePeriodCost;

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

    function test_JobWithdraw_OnlyUSDC() public {
        uint64 _withdrawAmount = Utils.usdc(10);

        vm.startPrank(user);
        vm.expectEmit();
        emit Market.MarketTokenWithdrew(jobId, _now(), user, _withdrawAmount);
        vm.expectEmit();
        emit Market.MarketJobWithdrew(jobId, _now(), _withdrawAmount, user);
        market.jobWithdraw(jobId, _withdrawAmount);
        vm.stopPrank();

        assertEq(
            market,
            jobId,
            Market.Job(
                "abcd",
                user,
                provider,
                Utils.JOB_RATE,
                initialBalance - noticePeriodCost - _withdrawAmount,
                _now(),
                Utils.JOB_RATE
            )
        );

        assertEq(market.creditBalances(jobId), initialCreditBalance - noticePeriodCost);

        assertEq(usdc.balanceOf(user), _withdrawAmount);
        assertEq(usdc.balanceOf(address(market)), initialTokenBalance - _withdrawAmount);
        assertEq(usdc.balanceOf(provider), noticePeriodCost);
        assertEq(usdc.balanceOf(address(credit)), creditTokenBalance - noticePeriodCost);
        assertEq(credit.balanceOf(user), 0);
        assertEq(credit.balanceOf(address(market)), initialCreditBalance - noticePeriodCost);
        assertEq(credit.balanceOf(provider), 0);
    }

    function test_JobWithdraw_OnlyCredit() public {
        uint64 _withdrawAmount = Utils.usdc(30);
        uint64 _tokenWithdrawAmount = initialTokenBalance;
        uint64 _creditWithdrawAmount = _withdrawAmount - _tokenWithdrawAmount;

        vm.startPrank(user);
        vm.expectEmit();
        emit Market.MarketTokenWithdrew(jobId, _now(), user, _tokenWithdrawAmount);
        vm.expectEmit();
        emit Market.MarketCreditTokenWithdrew(jobId, _now(), user, _creditWithdrawAmount);
        vm.expectEmit();
        emit Market.MarketJobWithdrew(jobId, _now(), _withdrawAmount, user);
        market.jobWithdraw(jobId, _withdrawAmount);
        vm.stopPrank();

        assertEq(
            market,
            jobId,
            Market.Job(
                "abcd",
                user,
                provider,
                Utils.JOB_RATE,
                initialBalance - noticePeriodCost - _withdrawAmount,
                _now(),
                Utils.JOB_RATE
            )
        );

        assertEq(market.creditBalances(jobId), initialCreditBalance - noticePeriodCost - _creditWithdrawAmount);

        assertEq(usdc.balanceOf(user), _tokenWithdrawAmount);
        assertEq(usdc.balanceOf(address(market)), initialTokenBalance - _tokenWithdrawAmount);
        assertEq(usdc.balanceOf(provider), noticePeriodCost);
        assertEq(usdc.balanceOf(address(credit)), creditTokenBalance - noticePeriodCost);
        assertEq(credit.balanceOf(user), _creditWithdrawAmount);
        assertEq(credit.balanceOf(address(market)), initialCreditBalance - noticePeriodCost - _creditWithdrawAmount);
        assertEq(credit.balanceOf(provider), 0);
    }

    function test_JobWithdraw_NotOwner() public {
        vm.expectRevert(Market.MarketJobOnlyOwner.selector);
        vm.startPrank(provider);
        market.jobWithdraw(jobId, Utils.usdc(10));
        vm.stopPrank();
    }

    function test_JobWithdraw_Inactive() public {
        vm.startPrank(user);
        skip(3000);
        vm.expectRevert(Market.MarketJobInactive.selector);
        market.jobWithdraw(jobId, Utils.usdc(10));
        vm.stopPrank();
    }

    function test_JobWithdraw_NonExistent() public {
        vm.startPrank(user);
        vm.expectRevert(Market.MarketJobOnlyOwner.selector);
        market.jobWithdraw(jobId + 1, Utils.usdc(10));
        vm.stopPrank();
    }
}

contract MarketTestJobWithdrawNoCredit is MarketTest {
    Market market;
    ERC20Mock usdc;
    uint64 jobId;
    address user;
    address provider;
    uint64 initialBalance;
    uint64 noticePeriodCost;

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

    function test_JobWithdraw_OnlyUSDC() public {
        uint64 _withdrawAmount = Utils.usdc(10);

        vm.startPrank(user);
        vm.expectEmit();
        emit Market.MarketTokenWithdrew(jobId, _now(), user, _withdrawAmount);
        vm.expectEmit();
        emit Market.MarketJobWithdrew(jobId, _now(), _withdrawAmount, user);
        market.jobWithdraw(jobId, _withdrawAmount);
        vm.stopPrank();

        assertEq(
            market,
            jobId,
            Market.Job(
                "abcd",
                user,
                provider,
                Utils.JOB_RATE,
                initialBalance - noticePeriodCost - _withdrawAmount,
                _now(),
                Utils.JOB_RATE
            )
        );

        assertEq(usdc.balanceOf(user), _withdrawAmount);
        assertEq(usdc.balanceOf(address(market)), initialBalance - noticePeriodCost - _withdrawAmount);
        assertEq(usdc.balanceOf(provider), noticePeriodCost);
    }

    function test_JobWithdraw_NotOwner() public {
        vm.expectRevert(Market.MarketJobOnlyOwner.selector);
        vm.startPrank(provider);
        market.jobWithdraw(jobId, Utils.usdc(10));
        vm.stopPrank();
    }

    function test_JobWithdraw_Inactive() public {
        vm.startPrank(user);
        skip(3000);
        vm.expectRevert(Market.MarketJobInactive.selector);
        market.jobWithdraw(jobId, Utils.usdc(10));
        vm.stopPrank();
    }

    function test_JobWithdraw_NonExistent() public {
        vm.startPrank(user);
        vm.expectRevert(Market.MarketJobOnlyOwner.selector);
        market.jobWithdraw(jobId + 1, Utils.usdc(10));
        vm.stopPrank();
    }
}

contract MarketTestJobClose is MarketTest {
    Market market;
    ERC20Mock usdc;
    CreditMock credit;
    uint64 creditTokenBalance;
    uint64 jobId;
    address user;
    address provider;
    uint64 initialBalance;
    uint64 initialTokenBalance;
    uint64 initialCreditBalance;
    uint64 noticePeriodCost;

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

    function test_JobClose() public {
        vm.startPrank(user);
        vm.expectEmit();
        emit Market.MarketTokenWithdrew(jobId, _now(), user, initialTokenBalance);
        vm.expectEmit();
        emit Market.MarketCreditTokenWithdrew(jobId, _now(), user, initialCreditBalance - noticePeriodCost);
        vm.expectEmit();
        emit Market.MarketJobWithdrew(jobId, _now(), initialBalance - noticePeriodCost, user);
        vm.expectEmit();
        emit Market.MarketJobClosed(jobId, _now());
        market.jobClose(jobId);
        vm.stopPrank();

        assertEq(market, jobId, Market.Job("", address(0), address(0), 0, 0, 0, 0));

        assertEq(market.creditBalances(jobId), 0);

        assertEq(usdc.balanceOf(user), initialTokenBalance);
        assertEq(usdc.balanceOf(address(market)), 0);
        assertEq(usdc.balanceOf(provider), noticePeriodCost);
        assertEq(usdc.balanceOf(address(credit)), creditTokenBalance - noticePeriodCost);
        assertEq(credit.balanceOf(user), initialCreditBalance - noticePeriodCost);
        assertEq(credit.balanceOf(address(market)), 0);
        assertEq(credit.balanceOf(provider), 0);
    }

    function test_JobClose_NotOwner() public {
        vm.expectRevert(Market.MarketJobOnlyOwner.selector);
        vm.startPrank(provider);
        market.jobClose(jobId);
        vm.stopPrank();
    }

    function test_JobClose_Inactive() public {
        vm.startPrank(user);
        skip(3000);

        uint64 _creditSettleAmount = initialCreditBalance - noticePeriodCost;
        uint64 _tokenSettleAmount = (initialBalance - noticePeriodCost) - _creditSettleAmount;

        vm.expectEmit();
        emit Market.MarketCreditTokenSettled(jobId, _now(), provider, _creditSettleAmount);
        vm.expectEmit();
        emit Market.MarketTokenSettled(jobId, _now(), provider, _tokenSettleAmount);
        vm.expectEmit();
        emit Market.MarketJobSettled(jobId, _now(), initialBalance - noticePeriodCost, provider);
        vm.expectEmit();
        emit Market.MarketJobClosed(jobId, _now());
        market.jobClose(jobId);
        vm.stopPrank();

        assertEq(market, jobId, Market.Job("", address(0), address(0), 0, 0, 0, 0));

        assertEq(market.creditBalances(jobId), 0);

        assertEq(usdc.balanceOf(user), 0);
        assertEq(usdc.balanceOf(address(market)), 0);
        assertEq(usdc.balanceOf(provider), initialBalance);
        assertEq(usdc.balanceOf(address(credit)), creditTokenBalance - noticePeriodCost - _creditSettleAmount);
        assertEq(credit.balanceOf(user), 0);
        assertEq(credit.balanceOf(address(market)), 0);
        assertEq(credit.balanceOf(provider), 0);
    }

    function test_JobClose_Overflow() public {
        vm.startPrank(user);
        skip(2 ** 62);

        vm.expectRevert(Market.MarketOutOfRange.selector);
        market.jobClose(jobId);
        vm.stopPrank();
    }

    function test_JobClose_AlreadyClosed() public {
        vm.startPrank(user);
        market.jobClose(jobId);

        vm.expectRevert(Market.MarketJobOnlyOwner.selector);
        market.jobClose(jobId);
        vm.stopPrank();
    }

    function test_JobClose_NonExistent() public {
        vm.startPrank(user);
        vm.expectRevert(Market.MarketJobOnlyOwner.selector);
        market.jobClose(jobId + 1);
        vm.stopPrank();
    }
}

contract MarketTestJobCloseNoCredit is MarketTest {
    Market market;
    ERC20Mock usdc;
    uint64 jobId;
    address user;
    address provider;
    uint64 initialBalance;
    uint64 noticePeriodCost;

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

    function test_JobClose() public {
        vm.startPrank(user);
        vm.expectEmit();
        emit Market.MarketTokenWithdrew(jobId, _now(), user, initialBalance - noticePeriodCost);
        vm.expectEmit();
        emit Market.MarketJobWithdrew(jobId, _now(), initialBalance - noticePeriodCost, user);
        vm.expectEmit();
        emit Market.MarketJobClosed(jobId, _now());
        market.jobClose(jobId);
        vm.stopPrank();

        assertEq(market, jobId, Market.Job("", address(0), address(0), 0, 0, 0, 0));

        assertEq(usdc.balanceOf(user), initialBalance - noticePeriodCost);
        assertEq(usdc.balanceOf(address(market)), 0);
        assertEq(usdc.balanceOf(provider), noticePeriodCost);
    }

    function test_JobClose_NotOwner() public {
        vm.expectRevert(Market.MarketJobOnlyOwner.selector);
        vm.startPrank(provider);
        market.jobClose(jobId);
        vm.stopPrank();
    }

    function test_JobClose_Inactive() public {
        vm.startPrank(user);
        skip(3000);

        uint64 _settleAmount = initialBalance - noticePeriodCost;

        vm.expectEmit();
        emit Market.MarketTokenSettled(jobId, _now(), provider, _settleAmount);
        vm.expectEmit();
        emit Market.MarketJobSettled(jobId, _now(), _settleAmount, provider);
        vm.expectEmit();
        emit Market.MarketJobClosed(jobId, _now());
        market.jobClose(jobId);
        vm.stopPrank();

        assertEq(market, jobId, Market.Job("", address(0), address(0), 0, 0, 0, 0));

        assertEq(usdc.balanceOf(user), 0);
        assertEq(usdc.balanceOf(address(market)), 0);
        assertEq(usdc.balanceOf(provider), initialBalance);
    }

    function test_JobClose_AlreadyClosed() public {
        vm.startPrank(user);
        market.jobClose(jobId);

        vm.expectRevert(Market.MarketJobOnlyOwner.selector);
        market.jobClose(jobId);
        vm.stopPrank();
    }

    function test_JobClose_NonExistent() public {
        vm.startPrank(user);
        vm.expectRevert(Market.MarketJobOnlyOwner.selector);
        market.jobClose(jobId + 1);
        vm.stopPrank();
    }
}

contract MarketTestJobReviseRate is MarketTest {
    Market market;
    ERC20Mock usdc;
    CreditMock credit;
    uint64 creditTokenBalance;
    uint64 jobId;
    address user;
    address provider;
    uint64 initialBalance;
    uint64 initialTokenBalance;
    uint64 initialCreditBalance;
    uint64 noticePeriodCost;

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

    function test_JobReviseRate_Increase() public {
        uint64 _newRate = Utils.JOB_RATE * 2;
        uint64 _extraNoticePeriodCost = Utils.calcAmountToPay(_newRate - Utils.JOB_RATE, Utils.NOTICE_PERIOD);

        vm.startPrank(user);
        vm.expectEmit();
        emit Market.MarketCreditTokenSettled(jobId, _now(), provider, _extraNoticePeriodCost);
        vm.expectEmit();
        emit Market.MarketJobSettled(jobId, _now(), _extraNoticePeriodCost, provider);
        vm.expectEmit();
        emit Market.MarketJobRateRevised(jobId, _now(), _newRate);
        market.jobReviseRate(jobId, _newRate);
        vm.stopPrank();

        assertEq(
            market,
            jobId,
            Market.Job(
                "abcd",
                user,
                provider,
                _newRate,
                initialBalance - noticePeriodCost - _extraNoticePeriodCost,
                _now(),
                _newRate
            )
        );

        assertEq(market.creditBalances(jobId), initialCreditBalance - noticePeriodCost - _extraNoticePeriodCost);

        assertEq(usdc.balanceOf(user), 0);
        assertEq(usdc.balanceOf(address(market)), initialTokenBalance);
        assertEq(usdc.balanceOf(provider), noticePeriodCost + _extraNoticePeriodCost);
        assertEq(credit.balanceOf(user), 0);
        assertEq(credit.balanceOf(address(market)), initialCreditBalance - noticePeriodCost - _extraNoticePeriodCost);
        assertEq(credit.balanceOf(provider), 0);
    }

    function test_JobReviseRate_IncreaseHitToken() public {
        uint64 _newRate = Utils.JOB_RATE * 6; // To exceed the remaining credit balance (30 - 6 = 24). Extra is 30.
        uint64 _extraNoticePeriodCost = Utils.calcAmountToPay(_newRate - Utils.JOB_RATE, Utils.NOTICE_PERIOD);
        uint64 _creditRemaining = initialCreditBalance - noticePeriodCost;

        vm.startPrank(user);
        vm.expectEmit();
        emit Market.MarketCreditTokenSettled(jobId, _now(), provider, _creditRemaining);
        vm.expectEmit();
        emit Market.MarketTokenSettled(jobId, _now(), provider, _extraNoticePeriodCost - _creditRemaining);
        vm.expectEmit();
        emit Market.MarketJobSettled(jobId, _now(), _extraNoticePeriodCost, provider);
        vm.expectEmit();
        emit Market.MarketJobRateRevised(jobId, _now(), _newRate);
        market.jobReviseRate(jobId, _newRate);
        vm.stopPrank();

        assertEq(
            market,
            jobId,
            Market.Job(
                "abcd",
                user,
                provider,
                _newRate,
                initialBalance - noticePeriodCost - _extraNoticePeriodCost,
                _now(),
                _newRate
            )
        );

        assertEq(market.creditBalances(jobId), 0);

        assertEq(usdc.balanceOf(user), 0);
        assertEq(usdc.balanceOf(address(market)), initialTokenBalance - (_extraNoticePeriodCost - _creditRemaining));
        assertEq(usdc.balanceOf(provider), noticePeriodCost + _extraNoticePeriodCost);
        assertEq(credit.balanceOf(user), 0);
        assertEq(credit.balanceOf(address(market)), 0);
        assertEq(credit.balanceOf(provider), 0);
    }

    function test_JobReviseRate_Decrease() public {
        uint64 _newRate = Utils.JOB_RATE / 2;

        vm.startPrank(user);
        vm.expectEmit();
        emit Market.MarketJobRateRevised(jobId, _now(), _newRate);
        market.jobReviseRate(jobId, _newRate);
        vm.stopPrank();

        assertEq(
            market,
            jobId,
            Market.Job("abcd", user, provider, _newRate, initialBalance - noticePeriodCost, _now(), Utils.JOB_RATE)
        );

        assertEq(market.creditBalances(jobId), initialCreditBalance - noticePeriodCost);

        assertEq(usdc.balanceOf(user), 0);
        assertEq(usdc.balanceOf(address(market)), initialTokenBalance);
        assertEq(usdc.balanceOf(provider), noticePeriodCost);
        assertEq(credit.balanceOf(user), 0);
        assertEq(credit.balanceOf(address(market)), initialCreditBalance - noticePeriodCost);
        assertEq(credit.balanceOf(provider), 0);
    }

    function test_JobReviseRate_DecreaseAndIncreaseBelowMax() public {
        uint64 _decreasedRate = Utils.JOB_RATE / 2;
        uint64 _increasedRate = Utils.JOB_RATE * 3 / 4;

        vm.startPrank(user);
        market.jobReviseRate(jobId, _decreasedRate);

        vm.expectEmit();
        emit Market.MarketJobRateRevised(jobId, _now(), _increasedRate);
        market.jobReviseRate(jobId, _increasedRate);
        vm.stopPrank();

        assertEq(
            market,
            jobId,
            Market.Job(
                "abcd", user, provider, _increasedRate, initialBalance - noticePeriodCost, _now(), Utils.JOB_RATE
            )
        );

        assertEq(market.creditBalances(jobId), initialCreditBalance - noticePeriodCost);

        assertEq(usdc.balanceOf(user), 0);
        assertEq(usdc.balanceOf(address(market)), initialTokenBalance);
        assertEq(usdc.balanceOf(provider), noticePeriodCost);
        assertEq(credit.balanceOf(user), 0);
        assertEq(credit.balanceOf(address(market)), initialCreditBalance - noticePeriodCost);
        assertEq(credit.balanceOf(provider), 0);
    }

    function test_JobReviseRate_NotOwner() public {
        vm.expectRevert(Market.MarketJobOnlyOwner.selector);
        vm.startPrank(provider);
        market.jobReviseRate(jobId, Utils.JOB_RATE * 2);
        vm.stopPrank();
    }

    function test_JobReviseRate_Inactive() public {
        vm.startPrank(user);
        skip(3000);
        vm.expectRevert(Market.MarketJobInactive.selector);
        market.jobReviseRate(jobId, Utils.JOB_RATE * 2);
        vm.stopPrank();
    }

    function test_JobReviseRate_NonExistent() public {
        vm.startPrank(user);
        vm.expectRevert(Market.MarketJobOnlyOwner.selector);
        market.jobReviseRate(jobId + 1, Utils.JOB_RATE * 2);
        vm.stopPrank();
    }
}

contract MarketTestJobReviseRateNoCredit is MarketTest {
    Market market;
    ERC20Mock usdc;
    uint64 jobId;
    address user;
    address provider;
    uint64 initialBalance;
    uint64 noticePeriodCost;

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

    function test_JobReviseRate_Increase() public {
        uint64 _newRate = Utils.JOB_RATE * 2;
        uint64 _extraNoticePeriodCost = Utils.calcAmountToPay(_newRate - Utils.JOB_RATE, Utils.NOTICE_PERIOD);

        vm.startPrank(user);
        vm.expectEmit();
        emit Market.MarketTokenSettled(jobId, _now(), provider, _extraNoticePeriodCost);
        vm.expectEmit();
        emit Market.MarketJobSettled(jobId, _now(), _extraNoticePeriodCost, provider);
        vm.expectEmit();
        emit Market.MarketJobRateRevised(jobId, _now(), _newRate);
        market.jobReviseRate(jobId, _newRate);
        vm.stopPrank();

        assertEq(
            market,
            jobId,
            Market.Job(
                "abcd",
                user,
                provider,
                _newRate,
                initialBalance - noticePeriodCost - _extraNoticePeriodCost,
                _now(),
                _newRate
            )
        );

        assertEq(usdc.balanceOf(user), 0);
        assertEq(usdc.balanceOf(address(market)), initialBalance - noticePeriodCost - _extraNoticePeriodCost);
        assertEq(usdc.balanceOf(provider), noticePeriodCost + _extraNoticePeriodCost);
    }

    function test_JobReviseRate_Decrease() public {
        uint64 _newRate = Utils.JOB_RATE / 2;

        vm.startPrank(user);
        vm.expectEmit();
        emit Market.MarketJobRateRevised(jobId, _now(), _newRate);
        market.jobReviseRate(jobId, _newRate);
        vm.stopPrank();

        assertEq(
            market,
            jobId,
            Market.Job("abcd", user, provider, _newRate, initialBalance - noticePeriodCost, _now(), Utils.JOB_RATE)
        );

        assertEq(usdc.balanceOf(user), 0);
        assertEq(usdc.balanceOf(address(market)), initialBalance - noticePeriodCost);
        assertEq(usdc.balanceOf(provider), noticePeriodCost);
    }

    function test_JobReviseRate_DecreaseAndIncreaseBelowMax() public {
        uint64 _decreasedRate = Utils.JOB_RATE / 2;
        uint64 _increasedRate = Utils.JOB_RATE * 3 / 4;

        vm.startPrank(user);
        market.jobReviseRate(jobId, _decreasedRate);

        vm.expectEmit();
        emit Market.MarketJobRateRevised(jobId, _now(), _increasedRate);
        market.jobReviseRate(jobId, _increasedRate);
        vm.stopPrank();

        assertEq(
            market,
            jobId,
            Market.Job(
                "abcd", user, provider, _increasedRate, initialBalance - noticePeriodCost, _now(), Utils.JOB_RATE
            )
        );

        assertEq(usdc.balanceOf(user), 0);
        assertEq(usdc.balanceOf(address(market)), initialBalance - noticePeriodCost);
        assertEq(usdc.balanceOf(provider), noticePeriodCost);
    }

    function test_JobReviseRate_NotOwner() public {
        vm.expectRevert(Market.MarketJobOnlyOwner.selector);
        vm.startPrank(provider);
        market.jobReviseRate(jobId, Utils.JOB_RATE * 2);
        vm.stopPrank();
    }

    function test_JobReviseRate_Inactive() public {
        vm.startPrank(user);
        skip(3000);
        vm.expectRevert(Market.MarketJobInactive.selector);
        market.jobReviseRate(jobId, Utils.JOB_RATE * 2);
        vm.stopPrank();
    }

    function test_JobReviseRate_NonExistent() public {
        vm.startPrank(user);
        vm.expectRevert(Market.MarketJobOnlyOwner.selector);
        market.jobReviseRate(jobId + 1, Utils.JOB_RATE * 2);
        vm.stopPrank();
    }
}

contract MarketTestJobMetadataUpdate is MarketTest {
    Market market;
    ERC20Mock usdc;
    CreditMock credit;
    uint64 creditTokenBalance;
    uint64 jobId;
    address user;
    address provider;
    uint64 initialBalance;
    uint64 initialTokenBalance;
    uint64 initialCreditBalance;
    uint64 noticePeriodCost;

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

    function test_JobMetadataUpdate() public {
        string memory _newMetadata = "efgh";

        vm.startPrank(user);
        vm.expectEmit();
        emit Market.MarketJobMetadataUpdated(jobId, _now(), _newMetadata);
        market.jobMetadataUpdate(jobId, _newMetadata);
        vm.stopPrank();

        assertEq(
            market,
            jobId,
            Market.Job(
                _newMetadata, user, provider, Utils.JOB_RATE, initialBalance - noticePeriodCost, _now(), Utils.JOB_RATE
            )
        );
    }

    function test_JobMetadataUpdate_NotOwner() public {
        vm.expectRevert(Market.MarketJobOnlyOwner.selector);
        vm.startPrank(provider);
        market.jobMetadataUpdate(jobId, "efgh");
        vm.stopPrank();
    }

    function test_JobMetadataUpdate_Inactive() public {
        vm.startPrank(user);
        skip(3000);
        vm.expectRevert(Market.MarketJobInactive.selector);
        market.jobMetadataUpdate(jobId, "efgh");
        vm.stopPrank();
    }

    function test_JobMetadataUpdate_NonExistent() public {
        vm.startPrank(user);
        vm.expectRevert(Market.MarketJobOnlyOwner.selector);
        market.jobMetadataUpdate(jobId + 1, "efgh");
        vm.stopPrank();
    }
}

contract MarketTestEmergencyWithdrawCredit is MarketTest {
    Market market;
    ERC20Mock usdc;
    CreditMock credit;
    uint64 creditTokenBalance;
    uint64 jobId;
    address user;
    address provider;
    address admin;
    uint64 initialBalance;
    uint64 initialTokenBalance;
    uint64 initialCreditBalance;
    uint64 noticePeriodCost;

    function setUp() public {
        admin = vm.randomAddress();
        usdc = new ERC20Mock("Circle USD", "USDC");
        credit = new CreditMock(usdc);
        creditTokenBalance = Utils.usdc(1000);
        usdc.mint(address(credit), creditTokenBalance);
        jobId = uint64(vm.randomUint(0, 10000));
        market = Market(
            Upgrades.deployUUPSProxy(
                "Market.sol",
                abi.encodeCall(Market.initialize, (admin, jobId, Utils.NOTICE_PERIOD, address(usdc), address(credit))),
                upgradeOptions()
            )
        );
        do {
            user = vm.randomAddress();
        } while (user == address(0) || user == address(market) || user == address(credit) || user == admin);
        do {
            provider = vm.randomAddress();
        } while (
            provider == address(0) || provider == address(market) || provider == address(credit) || provider == user
                || provider == admin
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

    function test_EmergencyWithdrawCredit() public {
        vm.startPrank(admin);

        uint64[] memory jobIds = new uint64[](1);
        jobIds[0] = jobId;

        uint64 _creditAmount = initialCreditBalance - noticePeriodCost;

        vm.expectEmit();
        emit Market.MarketCreditTokenSettled(jobId, _now(), provider, 0);
        vm.expectEmit();
        emit Market.MarketJobSettled(jobId, _now(), 0, provider);
        vm.expectEmit();
        emit Market.MarketCreditTokenWithdrew(jobId, _now(), admin, _creditAmount);
        vm.expectEmit();
        emit Market.MarketJobWithdrew(jobId, _now(), _creditAmount, admin);
        market.emergencyWithdrawCredit(admin, jobIds);
        vm.stopPrank();

        assertEq(
            market,
            jobId,
            Market.Job(
                "abcd",
                user,
                provider,
                Utils.JOB_RATE,
                initialBalance - noticePeriodCost - _creditAmount,
                _now(),
                Utils.JOB_RATE
            )
        );

        assertEq(market.creditBalances(jobId), 0);
        assertEq(credit.balanceOf(admin), _creditAmount);
        assertEq(credit.balanceOf(address(market)), 0);
    }

    function test_EmergencyWithdrawCredit_NotAdmin() public {
        uint64[] memory jobIds = new uint64[](1);
        jobIds[0] = jobId;

        vm.startPrank(user);
        vm.expectRevert(Market.MarketOnlyAdmin.selector);
        market.emergencyWithdrawCredit(user, jobIds);
        vm.stopPrank();
    }
}
