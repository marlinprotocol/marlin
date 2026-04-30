// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {DeployScript} from "./DeployScript.s.sol";
import {KmsRoot} from "../src/kms/KmsRoot.sol";
import {IRiscZeroVerifier} from "risc0-ethereum/IRiscZeroVerifier.sol";

contract DeployKmsRoot is DeployScript {
    constructor() DeployScript(vm.envString("KMS_ROOT_NAME")) {}

    function run() public {
        // collect params
        address _admin = _getDeployed("KmsAdmin");
        IRiscZeroVerifier _verifier = IRiscZeroVerifier(_getDeployed("RiscZeroVerifier"));
        bytes32 _guestId = _getConfigBytes32("guestId", "Kms");
        bytes memory _rootKey = _getConfigBytes("rootKey", "Kms");
        uint256 _maxAgeMs = _getConfigUint256("maxAgeMs", "Kms");
        bytes32 _imageId = _getConfigBytes32("imageId", "Kms");

        // deploy
        vm.startBroadcast();
        KmsRoot _kmsRoot = new KmsRoot(_admin, _admin, _admin, _verifier, _guestId, _rootKey, _maxAgeMs, _imageId);
        vm.stopBroadcast();

        // record address
        _setDeployed(address(_kmsRoot));
    }
}
