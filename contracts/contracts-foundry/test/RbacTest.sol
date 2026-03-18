// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test} from "./Test.sol";
import {IAccessControl} from "@openzeppelin/contracts/access/IAccessControl.sol";

abstract contract RbacAdminTest is Test {
    IAccessControl public uut;
    address public admin;
    bytes32 public constant DEFAULT_ADMIN_ROLE = bytes32(0);

    function _rbacAdminDeployContract(address _admin) internal virtual returns (IAccessControl);

    function setUp() public virtual {
        admin = vm.randomAddress();
        uut = _rbacAdminDeployContract(admin);
    }

    function test_AdminRole_AdminCanGrantAdminRole(address _otherAdmin)
        public
        assumeNotEqualAddress(_otherAdmin, admin)
    {
        vm.prank(admin);
        uut.grantRole(DEFAULT_ADMIN_ROLE, _otherAdmin);
        assertTrue(uut.hasRole(DEFAULT_ADMIN_ROLE, _otherAdmin));
    }

    function test_AdminRole_NonAdminCannotGrantAdminRole(address _nonAdmin)
        public
        assumeNotEqualAddress(_nonAdmin, admin)
    {
        vm.prank(_nonAdmin);
        vm.expectRevert();
        uut.grantRole(DEFAULT_ADMIN_ROLE, _nonAdmin);
    }

    function test_AdminRole_AdminCanRevokeAdminRole(address _otherAdmin)
        public
        assumeNotEqualAddress(_otherAdmin, admin)
    {
        vm.prank(admin);
        uut.grantRole(DEFAULT_ADMIN_ROLE, _otherAdmin);
        assertTrue(uut.hasRole(DEFAULT_ADMIN_ROLE, _otherAdmin));

        vm.prank(admin);
        uut.revokeRole(DEFAULT_ADMIN_ROLE, _otherAdmin);
        assertFalse(uut.hasRole(DEFAULT_ADMIN_ROLE, _otherAdmin));
    }

    function test_AdminRole_NonAdminCannotRevokeAdminRole(address _otherAdmin, address _nonAdmin)
        public
        assumeNotEqualAddress(_otherAdmin, admin)
        assumeNotEqualAddress(_nonAdmin, admin)
    {
        vm.prank(admin);
        uut.grantRole(DEFAULT_ADMIN_ROLE, _otherAdmin);
        assertTrue(uut.hasRole(DEFAULT_ADMIN_ROLE, _otherAdmin));

        vm.prank(_nonAdmin);
        vm.expectRevert();
        uut.revokeRole(DEFAULT_ADMIN_ROLE, _otherAdmin);
    }

    function test_AdminRole_AdminCanRenounceOwnAdminRole() public {
        vm.prank(admin);
        uut.renounceRole(DEFAULT_ADMIN_ROLE, admin);
        assertFalse(uut.hasRole(DEFAULT_ADMIN_ROLE, admin));
    }

    function test_AdminRole_AdminCannotRenounceAdminRoleOfOtherAdmins(address _otherAdmin)
        public
        assumeNotEqualAddress(_otherAdmin, admin)
    {
        vm.prank(admin);
        uut.grantRole(DEFAULT_ADMIN_ROLE, _otherAdmin);
        assertTrue(uut.hasRole(DEFAULT_ADMIN_ROLE, _otherAdmin));

        vm.prank(admin);
        vm.expectRevert();
        uut.renounceRole(DEFAULT_ADMIN_ROLE, _otherAdmin);
    }
}

abstract contract RbacRoleTest is Test {
    IAccessControl public uut;
    address public admin;
    bytes32 public role;

    function _rbacRoleDeployContract(address _admin) internal virtual returns (IAccessControl, bytes32);

    function setUp() public virtual {
        admin = vm.randomAddress();
        (uut, role) = _rbacRoleDeployContract(admin);
    }

    function test_Role_AdminCanGrantRole(address _user) public {
        vm.prank(admin);
        uut.grantRole(role, _user);
        assertTrue(uut.hasRole(role, _user));
    }

    function test_Role_NonAdminCannotGrantRole(address _user, address _nonAdmin)
        public
        assumeNotEqualAddress(_nonAdmin, admin)
    {
        vm.prank(_nonAdmin);
        vm.expectRevert();
        uut.grantRole(role, _user);
    }

    function test_Role_AdminCanRevokeRole(address _user) public {
        vm.prank(admin);
        uut.grantRole(role, _user);
        assertTrue(uut.hasRole(role, _user));

        vm.prank(admin);
        uut.revokeRole(role, _user);
        assertFalse(uut.hasRole(role, _user));
    }

    function test_Role_NonAdminCannotRevokeRole(address _user, address _nonAdmin)
        public
        assumeNotEqualAddress(_nonAdmin, admin)
    {
        vm.prank(admin);
        uut.grantRole(role, _user);
        assertTrue(uut.hasRole(role, _user));

        vm.prank(_nonAdmin);
        vm.expectRevert();
        uut.revokeRole(role, _user);
    }

    function test_Role_RoleSignerCanRenounceOwnRole(address _user) public {
        vm.prank(admin);
        uut.grantRole(role, _user);
        assertTrue(uut.hasRole(role, _user));

        vm.prank(_user);
        uut.renounceRole(role, _user);
        assertFalse(uut.hasRole(role, _user));
    }
}
