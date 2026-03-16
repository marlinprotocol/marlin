// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test} from "forge-std/Test.sol";
import {VerifiedKeys, VerifiedKeysDefault} from "../../src/attestation/VerifiedKeys.sol";

contract TestVerifiedKeys is VerifiedKeysDefault {
    bool public authorized;

    error NotAuthorized();

    function setAuthorized(bool _authorized) external {
        authorized = _authorized;
    }

    constructor(bytes32 _imageId, bytes32 _family, bool _authorized) VerifiedKeys(_imageId, _family) {
        authorized = _authorized;
    }

    function _vkAuthorizeApprove() internal virtual override {
        require(authorized, NotAuthorized());
    }

    function _vkAuthorizeRevoke() internal virtual override {
        require(authorized, NotAuthorized());
    }

    function _vkTransformPubkey(bytes memory _pubkey) internal pure override returns (bytes32) {
        return keccak256(_pubkey);
    }

    function setKeyVerified(bytes memory _enclavePubkey, bytes32 _imageId) external returns (bool) {
        return _setKeyVerified(_enclavePubkey, _imageId);
    }

    function ensureKeyVerified(bytes32 _key) external view {
        _ensureKeyVerified(_key);
    }

    function ensureKeyVerified(bytes32 _key, bytes32 _family) external view {
        _ensureKeyVerified(_key, _family);
    }
}

contract VerifiedKeysTestConstruction is Test {
    function test_Construction(bytes32 _imageId, bytes32 _family) public {
        vm.expectEmit();
        emit VerifiedKeys.VerifiedKeysApproved(_imageId, _family);

        TestVerifiedKeys verifiedKeys = new TestVerifiedKeys(_imageId, _family, true);

        assertEq(verifiedKeys.images(_imageId), _family);
    }
}

contract VerifiedKeysTestApproveImage is Test {
    bytes32 imageId;
    bytes32 family;
    TestVerifiedKeys verifiedKeys;

    function setUp() public {
        imageId = bytes32(vm.randomUint());
        family = bytes32(vm.randomUint());
        verifiedKeys = new TestVerifiedKeys(imageId, family, true);
    }

    function test_ApproveImage_Authorized(bytes32 _imageId, bytes32 _family) public {
        vm.expectEmit();
        emit VerifiedKeys.VerifiedKeysApproved(_imageId, _family);

        bool result = verifiedKeys.approveImage(_imageId, _family);

        assertTrue(result);
        assertEq(verifiedKeys.images(_imageId), _family);
    }

    function test_ApproveImage_Existing(bytes32 _imageId, bytes32 _family) public {
        verifiedKeys.approveImage(_imageId, _family);

        bool result = verifiedKeys.approveImage(_imageId, _family);

        assertFalse(result);
        assertEq(verifiedKeys.images(_imageId), _family);
    }

    function test_ApproveImage_Mismatch(bytes32 _imageId, bytes32 _family, bytes32 _otherFamily) public {
        verifiedKeys.approveImage(_imageId, _otherFamily);
        vm.expectRevert(VerifiedKeys.VerifiedKeysFamilyMismatch.selector);

        verifiedKeys.approveImage(_imageId, _family);
    }

    function test_ApproveImage_Unauthorized(bytes32 _imageId, bytes32 _family) public {
        verifiedKeys.setAuthorized(false);
        vm.expectRevert(TestVerifiedKeys.NotAuthorized.selector);

        verifiedKeys.approveImage(_imageId, _family);
    }
}

contract VerifiedKeysTestRevokeImage is Test {
    bytes32 imageId;
    bytes32 family;
    TestVerifiedKeys verifiedKeys;

    function setUp() public {
        imageId = bytes32(vm.randomUint());
        family = bytes32(vm.randomUint());
        verifiedKeys = new TestVerifiedKeys(imageId, family, true);
    }

    function test_RevokeImage_Authorized() public {
        vm.expectEmit();
        emit VerifiedKeys.VerifiedKeysRevoked(imageId, family);

        bool result = verifiedKeys.revokeImage(imageId);

        assertTrue(result);
        assertEq(verifiedKeys.images(imageId), bytes32(0));
    }

    function test_RevokeImage_NonExistent(bytes32 _imageId) public {
        vm.assume(_imageId != imageId);
        bool result = verifiedKeys.revokeImage(_imageId);

        assertFalse(result);
        assertEq(verifiedKeys.images(_imageId), bytes32(0));
    }

    function test_RevokeImage_Unauthorized() public {
        verifiedKeys.setAuthorized(false);
        vm.expectRevert(TestVerifiedKeys.NotAuthorized.selector);

        verifiedKeys.revokeImage(imageId);
    }
}

contract VerifiedKeysTestSetKeyVerified is Test {
    bytes32 imageId;
    bytes32 family;
    TestVerifiedKeys verifiedKeys;

    function setUp() public {
        imageId = bytes32(vm.randomUint());
        family = bytes32(vm.randomUint());
        verifiedKeys = new TestVerifiedKeys(imageId, family, true);
    }

    function test_SetKeyVerified_New(bytes memory _pubkey) public {
        bytes32 _transformedKey = keccak256(_pubkey);

        vm.expectEmit();
        emit VerifiedKeys.VerifiedKeysVerified(_transformedKey, imageId, _pubkey);

        bool result = verifiedKeys.setKeyVerified(_pubkey, imageId);

        assertTrue(result);
        assertEq(verifiedKeys.keys(_transformedKey), imageId);
    }

    function test_SetKeyVerified_Existing(bytes memory _pubkey) public {
        bytes32 _transformedKey = keccak256(_pubkey);
        verifiedKeys.setKeyVerified(_pubkey, imageId);

        bool result = verifiedKeys.setKeyVerified(_pubkey, imageId);

        assertFalse(result);
        assertEq(verifiedKeys.keys(_transformedKey), imageId);
    }

    function test_SetKeyVerified_Mismatch(bytes memory _pubkey, bytes32 _otherImageId) public {
        verifiedKeys.setKeyVerified(_pubkey, _otherImageId);
        vm.expectRevert(VerifiedKeys.VerifiedKeysImageMismatch.selector);

        verifiedKeys.setKeyVerified(_pubkey, imageId);
    }
}

contract VerifiedKeysTestEnsureKeyVerifiedDefaultFamily is Test {
    bytes32 imageId;
    bytes32 family;
    TestVerifiedKeys verifiedKeys;

    function setUp() public {
        imageId = bytes32(vm.randomUint());
        family = keccak256("DEFAULT_FAMILY");
        verifiedKeys = new TestVerifiedKeys(imageId, family, true);
    }

    function test_EnsureKeyVerified_Valid(bytes memory _pubkey) public {
        bytes32 key = keccak256(_pubkey);
        verifiedKeys.setKeyVerified(_pubkey, imageId);

        verifiedKeys.ensureKeyVerified(key);
    }

    function test_EnsureKeyVerified_NotVerified(bytes memory _pubkey) public {
        bytes32 key = keccak256(_pubkey);
        vm.expectRevert(VerifiedKeys.VerifiedKeysNotVerified.selector);

        verifiedKeys.ensureKeyVerified(key);
    }

    function test_EnsureKeyVerified_Revoked(bytes memory _pubkey) public {
        bytes32 key = keccak256(_pubkey);
        verifiedKeys.setKeyVerified(_pubkey, imageId);
        verifiedKeys.revokeImage(imageId);

        vm.expectRevert(VerifiedKeys.VerifiedKeysNotVerified.selector);
        verifiedKeys.ensureKeyVerified(key);
    }
}

contract VerifiedKeysTestEnsureKeyVerifiedCustomFamily is Test {
    bytes32 imageId;
    bytes32 family;
    TestVerifiedKeys verifiedKeys;

    function setUp() public {
        imageId = bytes32(vm.randomUint());
        family = bytes32(vm.randomUint());
        verifiedKeys = new TestVerifiedKeys(imageId, family, true);
    }

    function test_EnsureKeyVerified_Valid(bytes memory _pubkey) public {
        bytes32 key = keccak256(_pubkey);
        verifiedKeys.setKeyVerified(_pubkey, imageId);

        verifiedKeys.ensureKeyVerified(key, family);
    }

    function test_EnsureKeyVerified_NotVerified(bytes memory _pubkey) public {
        bytes32 key = keccak256(_pubkey);
        vm.expectRevert(VerifiedKeys.VerifiedKeysNotVerified.selector);

        verifiedKeys.ensureKeyVerified(key, family);
    }

    function test_EnsureKeyVerified_Revoked(bytes memory _pubkey) public {
        bytes32 key = keccak256(_pubkey);
        verifiedKeys.setKeyVerified(_pubkey, imageId);
        verifiedKeys.revokeImage(imageId);

        vm.expectRevert(VerifiedKeys.VerifiedKeysNotVerified.selector);
        verifiedKeys.ensureKeyVerified(key, family);
    }
}
