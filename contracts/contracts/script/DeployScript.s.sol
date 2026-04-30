// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Script, console2} from "forge-std/Script.sol";
import {stdJson} from "forge-std/StdJson.sol";
import {SafeCast} from "@openzeppelin/contracts/utils/math/SafeCast.sol";

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
        vm.toString(_value).write(path, _key);
        deployments = vm.readFile(path);
        console2.log(name, "deployed at", _value);
    }

    function _getConfigUint64(string memory _configKey, string memory _configName) internal returns (uint64) {
        string memory _key = string.concat(".", chainIdKey, ".", _configName, "Config.", _configKey);
        if (!deployments.keyExists(_key)) {
            revert(string.concat(_configName, " ", _configKey, " config not found"));
        }
        return SafeCast.toUint64(deployments.readUint(_key));
    }

    function _getConfigUint64(string memory _configKey) internal returns (uint64) {
        return _getConfigUint64(_configKey, name);
    }

    function _getConfigBytes32(string memory _configKey, string memory _configName) internal returns (bytes32) {
        string memory _key = string.concat(".", chainIdKey, ".", _configName, "Config.", _configKey);
        if (!deployments.keyExists(_key)) {
            revert(string.concat(_configName, " ", _configKey, " config not found"));
        }
        return deployments.readBytes32(_key);
    }

    function _getConfigBytes32(string memory _configKey) internal returns (bytes32) {
        return _getConfigBytes32(_configKey, name);
    }

    function _getConfigBytes(string memory _configKey, string memory _configName) internal returns (bytes memory) {
        string memory _key = string.concat(".", chainIdKey, ".", _configName, "Config.", _configKey);
        if (!deployments.keyExists(_key)) {
            revert(string.concat(_configName, " ", _configKey, " config not found"));
        }
        return deployments.readBytes(_key);
    }

    function _getConfigBytes(string memory _configKey) internal returns (bytes memory) {
        return _getConfigBytes(_configKey, name);
    }

    function _getConfigUint256(string memory _configKey, string memory _configName) internal returns (uint256) {
        string memory _key = string.concat(".", chainIdKey, ".", _configName, "Config.", _configKey);
        if (!deployments.keyExists(_key)) {
            revert(string.concat(_configName, " ", _configKey, " config not found"));
        }
        return deployments.readUint(_key);
    }

    function _getConfigUint256(string memory _configKey) internal returns (uint256) {
        return _getConfigUint256(_configKey, name);
    }
}
