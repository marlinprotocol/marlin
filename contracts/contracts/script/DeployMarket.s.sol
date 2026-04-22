// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {DeployScript} from "./DeployScript.s.sol";
import {Upgrades} from "openzeppelin-foundry-upgrades/Upgrades.sol";
import {Market} from "../src/market/Market.sol";

contract DeployMarket is DeployScript {
    constructor() DeployScript("Market") {}

    function run() public {
        // collect params
        address _admin = _getDeployed("Admin");
        uint64 _initialJobIndex = _getConfigUint64("initialJobIndex");
        uint64 _noticePeriod = _getConfigUint64("noticePeriod");
        address _token = _getDeployed("Usdc");
        address _creditToken = _getDeployed("Credit");

        // deploy
        vm.startBroadcast();
        address _proxy = Upgrades.deployUUPSProxy(
            "Market.sol",
            abi.encodeCall(Market.initialize, (_admin, _initialJobIndex, _noticePeriod, _token, _creditToken))
        );
        vm.stopBroadcast();

        // record address
        _setDeployed(_proxy);
    }
}
