// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test} from "../Test.sol";
import {Erc165Test} from "../Erc165Test.sol";
import {IERC165} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";
import {IAccessControl} from "@openzeppelin/contracts/access/IAccessControl.sol";
import {RbacAdminTest, RbacRoleTest} from "../RbacTest.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {Upgrades} from "openzeppelin-foundry-upgrades/Upgrades.sol";
import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {Credit} from "../../src/token/Credit.sol";
import {IERC20Errors} from "@openzeppelin/contracts/interfaces/draft-IERC6093.sol";
import {PausableUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

contract ERC20Mock is ERC20 {
    constructor(string memory name, string memory symbol) ERC20(name, symbol) {}

    function mint(address account, uint64 amount) public {
        _mint(account, amount);
    }
}

contract CreditErc165Test is Erc165Test {
    function _erc165DeployContract() internal virtual override returns (IERC165) {
        return IERC165(
            Upgrades.deployUUPSProxy(
                "Credit.sol",
                abi.encodeCall(Credit.initialize, (vm.randomAddress())),
                upgradeOptions(abi.encode(vm.randomAddress()))
            )
        );
    }

    function _erc165GetInterfaces() internal virtual override returns (bytes4[] memory) {
        bytes4[] memory interfaces = new bytes4[](1);
        interfaces[0] = type(IAccessControl).interfaceId;
        return interfaces;
    }
}

contract CreditRbacAdminTest is RbacAdminTest {
    function _rbacAdminDeployContract(address _admin) internal virtual override returns (IAccessControl) {
        return IAccessControl(
            Upgrades.deployUUPSProxy(
                "Credit.sol",
                abi.encodeCall(Credit.initialize, (_admin)),
                upgradeOptions(abi.encode(vm.randomAddress()))
            )
        );
    }
}

contract CreditMinterRoleTest is RbacRoleTest {
    function _rbacRoleDeployContract(address _admin) internal virtual override returns (IAccessControl, bytes32) {
        Credit credit = Credit(
            Upgrades.deployUUPSProxy(
                "Credit.sol",
                abi.encodeCall(Credit.initialize, (_admin)),
                upgradeOptions(abi.encode(vm.randomAddress()))
            )
        );
        return (IAccessControl(address(credit)), credit.MINTER_ROLE());
    }
}

contract CreditBurnerRoleTest is RbacRoleTest {
    function _rbacRoleDeployContract(address _admin) internal virtual override returns (IAccessControl, bytes32) {
        Credit credit = Credit(
            Upgrades.deployUUPSProxy(
                "Credit.sol",
                abi.encodeCall(Credit.initialize, (_admin)),
                upgradeOptions(abi.encode(vm.randomAddress()))
            )
        );
        return (IAccessControl(address(credit)), credit.BURNER_ROLE());
    }
}

contract CreditRedeemerRoleTest is RbacRoleTest {
    function _rbacRoleDeployContract(address _admin) internal virtual override returns (IAccessControl, bytes32) {
        Credit credit = Credit(
            Upgrades.deployUUPSProxy(
                "Credit.sol",
                abi.encodeCall(Credit.initialize, (_admin)),
                upgradeOptions(abi.encode(vm.randomAddress()))
            )
        );
        return (IAccessControl(address(credit)), credit.REDEEMER_ROLE());
    }
}

contract CreditTransferAllowedRoleTest is RbacRoleTest {
    function _rbacRoleDeployContract(address _admin) internal virtual override returns (IAccessControl, bytes32) {
        Credit credit = Credit(
            Upgrades.deployUUPSProxy(
                "Credit.sol",
                abi.encodeCall(Credit.initialize, (_admin)),
                upgradeOptions(abi.encode(vm.randomAddress()))
            )
        );
        return (IAccessControl(address(credit)), credit.TRANSFER_ALLOWED_ROLE());
    }
}

contract CreditPauserRoleTest is RbacRoleTest {
    function _rbacRoleDeployContract(address _admin) internal virtual override returns (IAccessControl, bytes32) {
        Credit credit = Credit(
            Upgrades.deployUUPSProxy(
                "Credit.sol",
                abi.encodeCall(Credit.initialize, (_admin)),
                upgradeOptions(abi.encode(vm.randomAddress()))
            )
        );
        return (IAccessControl(address(credit)), credit.PAUSER_ROLE());
    }
}

contract CreditEmergencyWithdrawRoleTest is RbacRoleTest {
    function _rbacRoleDeployContract(address _admin) internal virtual override returns (IAccessControl, bytes32) {
        Credit credit = Credit(
            Upgrades.deployUUPSProxy(
                "Credit.sol",
                abi.encodeCall(Credit.initialize, (_admin)),
                upgradeOptions(abi.encode(vm.randomAddress()))
            )
        );
        return (IAccessControl(address(credit)), credit.EMERGENCY_WITHDRAW_ROLE());
    }
}

contract CreditTestDeploy is Test {
    function upgradeHelper(address _proxy, address _usdc) public {
        vm.startPrank(msg.sender);
        Upgrades.upgradeProxy(_proxy, "Credit.sol", "", upgradeOptions(abi.encode(_usdc)));
        vm.stopPrank();
    }

    function test_Deploy_InitializationDisabled() public {
        Credit _credit = new Credit(vm.randomAddress());
        vm.expectRevert(Initializable.InvalidInitialization.selector);
        _credit.initialize(vm.randomAddress());
    }

    function test_Deploy_WithProxy(address _admin, address _usdc) public assumeNotEqualAddress(address(this), _admin) {
        vm.expectEmit();
        emit IAccessControl.RoleGranted(bytes32(0), _admin, address(this));
        Credit _credit = Credit(
            Upgrades.deployUUPSProxy(
                "Credit.sol", abi.encodeCall(Credit.initialize, (_admin)), upgradeOptions(abi.encode(_usdc))
            )
        );

        assertTrue(_credit.hasRole(_credit.DEFAULT_ADMIN_ROLE(), _admin));
        assertFalse(_credit.hasRole(_credit.DEFAULT_ADMIN_ROLE(), address(this)));
        assertEq(_credit.USDC(), _usdc);
        assertEq(_credit.decimals(), 6);
    }

    function test_Deploy_AdminCanUpgrade(address _admin, address _usdc)
        public
        assumeNotEqualAddress(address(this), _admin)
    {
        Credit _credit = Credit(
            Upgrades.deployUUPSProxy(
                "Credit.sol", abi.encodeCall(Credit.initialize, (_admin)), upgradeOptions(abi.encode(_usdc))
            )
        );

        vm.startPrank(_admin);
        Upgrades.upgradeProxy(address(_credit), "Credit.sol", "", upgradeOptions(abi.encode(_usdc)));
        vm.stopPrank();

        assertTrue(_credit.hasRole(_credit.DEFAULT_ADMIN_ROLE(), _admin));
    }

    function test_Deploy_NonAdminCannotUpgrade(address _admin, address _usdc)
        public
        assumeNotEqualAddress(address(this), _admin)
    {
        Credit _credit = Credit(
            Upgrades.deployUUPSProxy(
                "Credit.sol", abi.encodeCall(Credit.initialize, (_admin)), upgradeOptions(abi.encode(_usdc))
            )
        );

        vm.expectRevert(Credit.CreditOnlyAdmin.selector);
        this.upgradeHelper(address(_credit), _usdc);
    }
}

contract CreditTest is Test {
    Credit credit;
    ERC20Mock usdc;
    address admin;

    function setUp() public virtual {
        admin = vm.randomAddress();
        usdc = new ERC20Mock("USDC", "USDC");
        credit = Credit(
            Upgrades.deployUUPSProxy(
                "Credit.sol", abi.encodeCall(Credit.initialize, (admin)), upgradeOptions(abi.encode(address(usdc)))
            )
        );
    }
}

contract CreditTestMint is CreditTest {
    address minter;
    address user;

    function setUp() public override {
        super.setUp();
        minter = vm.randomAddress();
        user = vm.randomAddress();
        vm.startPrank(admin);
        credit.grantRole(credit.MINTER_ROLE(), minter);
        credit.grantRole(credit.TRANSFER_ALLOWED_ROLE(), user);
        vm.stopPrank();
    }

    function test_Mint_Valid(uint256 amount) public {
        vm.prank(minter);
        credit.mint(user, amount);
        assertEq(credit.balanceOf(user), amount);
    }

    function test_Mint_NotMinter(uint256 amount) public {
        vm.expectRevert(
            abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, user, credit.MINTER_ROLE())
        );
        vm.prank(user);
        credit.mint(user, amount);
    }

    function test_Mint_NotTransferAllowed(uint256 amount) public {
        address user2 = vm.randomAddress();
        vm.expectRevert(Credit.CreditOnlyTransferAllowedRole.selector);
        vm.prank(minter);
        credit.mint(user2, amount);
    }

    function test_Mint_Paused(uint256 amount) public {
        vm.startPrank(admin);
        credit.grantRole(credit.PAUSER_ROLE(), admin);
        credit.pause();
        vm.stopPrank();

        vm.expectRevert(PausableUpgradeable.EnforcedPause.selector);
        vm.prank(minter);
        credit.mint(user, amount);
    }
}

contract CreditTestBurn is CreditTest {
    address minter;
    address burner;
    address user;

    function setUp() public override {
        super.setUp();
        minter = vm.randomAddress();
        burner = vm.randomAddress();
        user = vm.randomAddress();
        vm.startPrank(admin);
        credit.grantRole(credit.MINTER_ROLE(), minter);
        credit.grantRole(credit.BURNER_ROLE(), burner);
        credit.grantRole(credit.TRANSFER_ALLOWED_ROLE(), user);
        vm.stopPrank();

        vm.prank(minter);
        credit.mint(user, 1000);
    }

    function test_Burn_Valid() public {
        vm.prank(burner);
        credit.burn(user, 500);
        assertEq(credit.balanceOf(user), 500);
    }

    function test_Burn_NotBurner() public {
        vm.expectRevert(
            abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, user, credit.BURNER_ROLE())
        );
        vm.prank(user);
        credit.burn(user, 500);
    }

    function test_Burn_NotTransferAllowed() public {
        address user2 = vm.randomAddress();
        vm.expectRevert(Credit.CreditOnlyTransferAllowedRole.selector);
        vm.prank(burner);
        credit.burn(user2, 500);
    }

    function test_Burn_Paused() public {
        vm.startPrank(admin);
        credit.grantRole(credit.PAUSER_ROLE(), admin);
        credit.pause();
        vm.stopPrank();

        vm.expectRevert(PausableUpgradeable.EnforcedPause.selector);
        vm.prank(burner);
        credit.burn(user, 500);
    }
}

contract CreditTestRedeemAndBurn is CreditTest {
    address minter;
    address redeemer;
    address user;
    address to;

    function setUp() public override {
        super.setUp();
        minter = vm.randomAddress();
        redeemer = vm.randomAddress();
        user = vm.randomAddress();
        to = vm.randomAddress();
        vm.startPrank(admin);
        credit.grantRole(credit.MINTER_ROLE(), minter);
        credit.grantRole(credit.REDEEMER_ROLE(), redeemer);
        credit.grantRole(credit.TRANSFER_ALLOWED_ROLE(), redeemer); // Redeemer needs transfer allowed to burn from itself
        vm.stopPrank();

        vm.prank(minter);
        credit.mint(redeemer, 1000); // Redeemer has the tokens

        usdc.mint(address(credit), 1000);
    }

    function test_RedeemAndBurn_Valid() public {
        vm.prank(redeemer);
        credit.redeemAndBurn(to, 500);
        assertEq(credit.balanceOf(redeemer), 500);
        assertEq(usdc.balanceOf(to), 500);
    }

    function test_RedeemAndBurn_NotRedeemer() public {
        vm.expectRevert(
            abi.encodeWithSelector(
                IAccessControl.AccessControlUnauthorizedAccount.selector, user, credit.REDEEMER_ROLE()
            )
        );
        vm.prank(user);
        credit.redeemAndBurn(to, 500);
    }

    function test_RedeemAndBurn_Paused() public {
        vm.startPrank(admin);
        credit.grantRole(credit.PAUSER_ROLE(), admin);
        credit.pause();
        vm.stopPrank();

        vm.expectRevert(PausableUpgradeable.EnforcedPause.selector);
        vm.prank(redeemer);
        credit.redeemAndBurn(to, 500);
    }
}

contract CreditTestEmergencyWithdraw is CreditTest {
    address emergencyRole;
    address user;

    function setUp() public override {
        super.setUp();
        emergencyRole = vm.randomAddress();
        user = vm.randomAddress();
        vm.startPrank(admin);
        credit.grantRole(credit.EMERGENCY_WITHDRAW_ROLE(), emergencyRole);
        vm.stopPrank();

        usdc.mint(address(credit), 1000);
    }

    function test_EmergencyWithdraw_Valid() public {
        vm.prank(admin);
        credit.emergencyWithdraw(address(usdc), emergencyRole, 500);
        assertEq(usdc.balanceOf(emergencyRole), 500);
    }

    function test_EmergencyWithdraw_NotAdmin() public {
        vm.expectRevert(Credit.CreditOnlyAdmin.selector);
        vm.prank(user);
        credit.emergencyWithdraw(address(usdc), emergencyRole, 500);
    }

    function test_EmergencyWithdraw_NotEmergencyRole() public {
        vm.expectRevert(Credit.CreditOnlyToEmergencyWithdrawRole.selector);
        vm.prank(admin);
        credit.emergencyWithdraw(address(usdc), user, 500);
    }
}

contract CreditTestPauseUnpause is CreditTest {
    address pauser;
    address user;

    function setUp() public override {
        super.setUp();
        pauser = vm.randomAddress();
        user = vm.randomAddress();
        vm.startPrank(admin);
        credit.grantRole(credit.PAUSER_ROLE(), pauser);
        vm.stopPrank();
    }

    function test_Pause_Valid() public {
        vm.prank(pauser);
        credit.pause();
        assertTrue(credit.paused());
    }

    function test_Pause_NotPauser() public {
        vm.expectRevert(
            abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, user, credit.PAUSER_ROLE())
        );
        vm.prank(user);
        credit.pause();
    }

    function test_Unpause_Valid() public {
        vm.prank(pauser);
        credit.pause();
        assertTrue(credit.paused());

        vm.prank(pauser);
        credit.unpause();
        assertFalse(credit.paused());
    }

    function test_Unpause_NotPauser() public {
        vm.prank(pauser);
        credit.pause();
        assertTrue(credit.paused());

        vm.expectRevert(
            abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, user, credit.PAUSER_ROLE())
        );
        vm.prank(user);
        credit.unpause();
    }
}

contract CreditTestTransfer is CreditTest {
    address minter;
    address userA;
    address userB;
    address userC;

    function setUp() public override {
        super.setUp();
        minter = vm.randomAddress();
        userA = vm.randomAddress();
        userB = vm.randomAddress();
        userC = vm.randomAddress();
        vm.startPrank(admin);
        credit.grantRole(credit.MINTER_ROLE(), minter);
        credit.grantRole(credit.TRANSFER_ALLOWED_ROLE(), userA);
        credit.grantRole(credit.TRANSFER_ALLOWED_ROLE(), userB);
        vm.stopPrank();

        vm.prank(minter);
        credit.mint(userA, 1000);
    }

    function test_Transfer_SenderAllowed() public {
        vm.prank(userA);
        credit.transfer(userC, 500);
        assertEq(credit.balanceOf(userA), 500);
        assertEq(credit.balanceOf(userC), 500);
    }

    function test_Transfer_RecipientAllowed() public {
        vm.prank(userA);
        credit.transfer(userC, 500); // C has 500, A has 500. C is not allowed but can receive because A is allowed.

        vm.prank(userC);
        credit.transfer(userB, 200); // C is not allowed, but B is allowed.
        assertEq(credit.balanceOf(userC), 300);
        assertEq(credit.balanceOf(userB), 200);
    }

    function test_Transfer_NeitherAllowed() public {
        vm.prank(userA);
        credit.transfer(userC, 500);

        address userD = vm.randomAddress();
        vm.expectRevert(Credit.CreditOnlyTransferAllowedRole.selector);
        vm.prank(userC);
        credit.transfer(userD, 200); // C is not allowed, D is not allowed.
    }
}
