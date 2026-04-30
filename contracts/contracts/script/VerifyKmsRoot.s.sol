// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {DeployScript} from "./DeployScript.s.sol";
import {KmsRoot} from "../src/kms/KmsRoot.sol";
import {IRiscZeroVerifier} from "risc0-ethereum/IRiscZeroVerifier.sol";
import {IAttestationVerifier} from "../src/attestation/IAttestationVerifier.sol";
import {SafeCast} from "@openzeppelin/contracts/utils/math/SafeCast.sol";

contract VerifyKmsRoot is DeployScript {
    // Bit of a hack
    constructor() DeployScript("NONEXISTENT") {}

    function run() public {
        // collect params
        KmsRoot _kmsRoot = KmsRoot(_getDeployed(vm.envString("KMS_ROOT_NAME")));
        bytes memory _seal = vm.envBytes("KMS_ROOT_SEAL");
        bytes32 _imageId = _getConfigBytes32("imageId", "Kms");
        uint64 _timestamp = SafeCast.toUint64(vm.envUint("KMS_ROOT_TS"));
        bytes memory _pubkey = vm.envBytes("KMS_ROOT_PUBKEY");
        bytes memory _userData = new bytes(0);

        // verify
        vm.startBroadcast();
        _kmsRoot.verify(_seal, IAttestationVerifier.Attestation(_imageId, _timestamp, _pubkey, _userData));
        vm.stopBroadcast();
    }
}
