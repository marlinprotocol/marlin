// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Script, console2} from "forge-std/Script.sol";
import {stdJson} from "forge-std/StdJson.sol";

contract DeployScript is Script {
    using stdJson for string;

    string public name;
    string public chainIdKey;
    string public path;
    string public deployments;

    constructor(string memory _name) {
        name = _name;

        chainIdKey = vm.toString(block.chainid);

        string memory _root = vm.projectRoot();
        path = string.concat(_root, "/deployments.json");
        deployments = "{}";
        if (vm.exists(path)) {
            deployments = vm.readFile(path);
        }
        
        _checkAlreadyDeployed();
    }

    function _checkAlreadyDeployed() internal {
        string memory _key = string.concat(".", chainIdKey, ".", name);
        if (deployments.keyExists(_key)) {
            address _value = deployments.readAddress(_key);
            revert(string.concat(name, " already deployed at ", vm.toString(_value)));
        }
    }

    function _getDeployed(string memory _name) internal returns (address) {
        string memory _key = string.concat(".", chainIdKey, ".", _name);
        if (!deployments.keyExists(_key)) {
            revert(string.concat(_name, " address not found"));
        }
        return deployments.readAddress(_key);
    }

    function _setDeployed(address _value) internal {
        string memory _key = string.concat(".", chainIdKey, ".", name);
        deployments = deployments.serialize(_key, _value);
        deployments.write(path);
        console2.log(name, "deployed at", _value);
    }
}
