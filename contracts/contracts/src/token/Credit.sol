// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

/* Libraries */
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

/* Contracts */
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {ContextUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/ContextUpgradeable.sol";
import {ERC165Upgradeable} from "@openzeppelin/contracts-upgradeable/utils/introspection/ERC165Upgradeable.sol";
import {AccessControlUpgradeable} from "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import {ERC20Upgradeable} from "@openzeppelin/contracts-upgradeable/token/ERC20/ERC20Upgradeable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {PausableUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";

/* Interfaces */
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {ICredit} from "./ICredit.sol";

/// @title   Credit
/// @notice  To transfer Credit tokens, either the sender or the recipient must have `TRANSFER_ALLOWED_ROLE`.
/// @dev     Admin must track the balance of USDC in the contract compared to the total supply of Credit.
contract Credit is
    Initializable, // initializer
    ContextUpgradeable, // _msgSender, _msgData
    ERC165Upgradeable, // supportsInterface
    AccessControlUpgradeable, // RBAC
    UUPSUpgradeable, // public upgrade
    ERC20Upgradeable, // token
    PausableUpgradeable, // pause/unpause
    ICredit
{
    using SafeERC20 for IERC20;

    error CreditNoAdminExists();
    error CreditOnlyAdmin();
    error CreditOnlyToEmergencyWithdrawRole();
    error CreditOnlyTransferAllowedRole();

    bytes32 public constant MINTER_ROLE = keccak256("MINTER_ROLE"); // 0x9f2df0fed2c77648de5860a4cc508cd0818c85b8b8a1ab4ceeef8d981c8956a6
    bytes32 public constant BURNER_ROLE = keccak256("BURNER_ROLE"); // 0x3c11d16cbaffd01df69ce1c404f6340ee057498f5f00246190ea54220576a848
    bytes32 public constant TRANSFER_ALLOWED_ROLE = keccak256("TRANSFER_ALLOWED_ROLE"); // 0xed89ee80d998965e2804dad373576bf7ffc490ba5986d52deb7d526e93617101
    bytes32 public constant REDEEMER_ROLE = keccak256("REDEEMER_ROLE"); // 0x44ac9762eec3a11893fefb11d028bb3102560094137c3ed4518712475b2577cc
    bytes32 public constant EMERGENCY_WITHDRAW_ROLE = keccak256("EMERGENCY_WITHDRAW_ROLE"); // 0x66f144ecd65ad16d38ecdba8687842af4bc05fde66fe3d999569a3006349785f
    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE"); // 0x65d7a28e3265b37a6474929f336521b332c1681b933f6cb9f3376673440d862a

    modifier onlyAdmin() {
        _onlyAdmin();
        _;
    }

    function _onlyAdmin() internal view {
        require(hasRole(DEFAULT_ADMIN_ROLE, _msgSender()), CreditOnlyAdmin());
    }

    /*---- Overrides start ----*/

    function supportsInterface(bytes4 interfaceId)
        public
        view
        virtual
        override(ERC165Upgradeable, AccessControlUpgradeable)
        returns (bool)
    {
        return super.supportsInterface(interfaceId);
    }

    function _authorizeUpgrade(address) internal view override onlyAdmin {}

    function decimals() public pure override(ERC20Upgradeable) returns (uint8) {
        return 6;
    }

    function _update(address from, address to, uint256 amount) internal virtual override(ERC20Upgradeable) {
        require(
            hasRole(TRANSFER_ALLOWED_ROLE, from) || hasRole(TRANSFER_ALLOWED_ROLE, to), CreditOnlyTransferAllowedRole()
        );
        return super._update(from, to, amount);
    }

    /*---- Overrides end ----*/

    /*---- Initializer start ----*/

    /// @custom:oz-upgrades-unsafe-allow state-variable-immutable
    address public immutable USDC;

    /// @custom:oz-upgrades-unsafe-allow constructor
    // disable all initializers and reinitializers
    // safeguard against takeover of the logic contract
    constructor(address _usdc) {
        _disableInitializers();

        USDC = _usdc;
    }

    function initialize(address _admin) public initializer {
        __Context_init_unchained();
        __ERC165_init_unchained();
        __AccessControl_init_unchained();
        __ERC20_init_unchained("Marlin Credit", "CREDIT");
        __Pausable_init_unchained();

        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
    }

    /*---- Initializer end ----*/

    /*---- Mint/Burn start ----*/

    /**
     * @notice  Mint Credit tokens.
     * @dev     Caller must have `MINTER_ROLE`.
     * @param   _to      Address to mint tokens to. Must have `TRANSFER_ALLOWED_ROLE`.
     * @param   _amount  Amount of tokens to mint.
     */
    function mint(address _to, uint256 _amount) external whenNotPaused onlyRole(MINTER_ROLE) {
        _mint(_to, _amount);
    }

    /**
     * @notice  Burn Credit tokens.
     * @dev     Caller must have `BURNER_ROLE`.
     * @param   _from    Address to burn tokens from. Must have `TRANSFER_ALLOWED_ROLE`
     * @param   _amount  Amount of tokens to burn.
     */
    function burn(address _from, uint256 _amount) external whenNotPaused onlyRole(BURNER_ROLE) {
        _burn(_from, _amount);
    }

    /*---- Mint/Burn end ----*/

    /*---- ICredit start ----*/

    /**
     * @notice  Burn Credit tokens and receive USDC.
     *          `_amount` of Credit tokens will be burned and `_amount` of USDC will be sent to `_to`.
     * @dev     Caller must have `REDEEMER_ROLE`.
     * @dev     Can revert if `Credit` contract does not have enough balance of USDC.
     * @param   _to      Address to receive USDC.
     * @param   _amount  Amount of tokens to redeem.
     */
    function redeemAndBurn(address _to, uint256 _amount) external whenNotPaused onlyRole(REDEEMER_ROLE) {
        _burn(_msgSender(), _amount);
        IERC20(USDC).safeTransfer(_to, _amount);
    }

    /*---- ICredit end ----*/

    /*---- Pause/Unpause start ----*/

    function pause() external onlyRole(PAUSER_ROLE) {
        _pause();
    }

    function unpause() external onlyRole(PAUSER_ROLE) {
        _unpause();
    }

    /*---- Pause/Unpause end ----*/

    /*---- Emergency Withdraw start ----*/

    /**
     * @notice  Emergency withdraw tokens from the contract.
     * @dev     Caller must have `DEFAULT_ADMIN_ROLE`
     *          and `_to` address must have `EMERGENCY_WITHDRAW_ROLE`.
     * @param   _token  Address of the token to withdraw.
     * @param   _to     Address to receive the tokens. Must have `EMERGENCY_WITHDRAW_ROLE`.
     * @param   _amount Amount of tokens to withdraw.
     */
    function emergencyWithdraw(address _token, address _to, uint256 _amount) external onlyAdmin {
        require(hasRole(EMERGENCY_WITHDRAW_ROLE, _to), CreditOnlyToEmergencyWithdrawRole());
        IERC20(_token).safeTransfer(_to, _amount);
    }

    /*---- Emergency Withdraw end ----*/
}
