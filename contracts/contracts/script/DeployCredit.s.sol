// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {DeployScript} from "./DeployScript.s.sol";
import {Upgrades} from "openzeppelin-foundry-upgrades/Upgrades.sol";
import {Options} from "openzeppelin-foundry-upgrades/Options.sol";
import {Credit} from "../src/token/Credit.sol";

contract DeployCredit is DeployScript {
    constructor() DeployScript("Credit") {}

    function run() public {
        // collect params
        address _admin = _getDeployed("Admin");
        address _usdc = _getDeployed("Usdc");

        Options memory _opts;
        _opts.constructorData = abi.encode(_usdc);

        // deploy
        vm.startBroadcast();
        address _proxy = Upgrades.deployUUPSProxy("Credit.sol", abi.encodeCall(Credit.initialize, (_admin)), _opts);
        vm.stopBroadcast();

        // record address
        _setDeployed(_proxy);
    }
}
