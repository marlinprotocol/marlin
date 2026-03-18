// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test as ForgeTest} from "forge-std/Test.sol";
import {Options} from "openzeppelin-foundry-upgrades/Options.sol";

contract Test is ForgeTest {
    modifier assume(bool x) {
        vm.assume(x);
        _;
    }

    modifier assumeNonZeroBytes32(bytes32 x) {
        vm.assume(x != bytes32(0));
        _;
    }

    modifier assumeNotEqualBytes32(bytes32 _a, bytes32 _b) {
        vm.assume(_a != _b);
        _;
    }

    modifier assumeNotEqualAddress(address _a, address _b) {
        vm.assume(_a != _b);
        _;
    }

    function randomUintNonZero() internal returns (uint256) {
        return vm.randomUint(1, type(uint256).max);
    }

    function randomBytes32NonZero() internal returns (bytes32) {
        return bytes32(randomUintNonZero());
    }

    function upgradeOptions() internal returns (Options memory) {
        Options memory options;
        options.unsafeSkipAllChecks = true;
        return options;
    }
}
