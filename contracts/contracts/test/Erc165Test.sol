// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test} from "./Test.sol";
import {IERC165} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";

abstract contract Erc165Test is Test {
    IERC165 public uut;

    function _erc165DeployContract() internal virtual returns (IERC165);
    function _erc165GetInterfaces() internal virtual returns (bytes4[] memory);

    function setUp() public {
        uut = _erc165DeployContract();
    }

    function test_SupportsInterface_SupportsErc165() public {
        assertTrue(uut.supportsInterface(type(IERC165).interfaceId));
    }

    function test_SupportsInterface_DoesNotSupportInvalidId() public {
        assertFalse(uut.supportsInterface(0xffffffff));
    }

    function test_SupportsInterface_SupportsInterfaces() public {
        bytes4[] memory interfaces = _erc165GetInterfaces();
        for (uint256 i = 0; i < interfaces.length; i++) {
            assertTrue(uut.supportsInterface(interfaces[i]));
        }
    }
}
