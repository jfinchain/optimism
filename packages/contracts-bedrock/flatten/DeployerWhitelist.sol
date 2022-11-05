// Dependency file: @openzeppelin/contracts/utils/Strings.sol

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts (last updated v4.7.0) (utils/Strings.sol)

// pragma solidity ^0.8.0;

/**
 * @dev String operations.
 */
library Strings {
    bytes16 private constant _HEX_SYMBOLS = "0123456789abcdef";
    uint8 private constant _ADDRESS_LENGTH = 20;

    /**
     * @dev Converts a `uint256` to its ASCII `string` decimal representation.
     */
    function toString(uint256 value) internal pure returns (string memory) {
        // Inspired by OraclizeAPI's implementation - MIT licence
        // https://github.com/oraclize/ethereum-api/blob/b42146b063c7d6ee1358846c198246239e9360e8/oraclizeAPI_0.4.25.sol

        if (value == 0) {
            return "0";
        }
        uint256 temp = value;
        uint256 digits;
        while (temp != 0) {
            digits++;
            temp /= 10;
        }
        bytes memory buffer = new bytes(digits);
        while (value != 0) {
            digits -= 1;
            buffer[digits] = bytes1(uint8(48 + uint256(value % 10)));
            value /= 10;
        }
        return string(buffer);
    }

    /**
     * @dev Converts a `uint256` to its ASCII `string` hexadecimal representation.
     */
    function toHexString(uint256 value) internal pure returns (string memory) {
        if (value == 0) {
            return "0x00";
        }
        uint256 temp = value;
        uint256 length = 0;
        while (temp != 0) {
            length++;
            temp >>= 8;
        }
        return toHexString(value, length);
    }

    /**
     * @dev Converts a `uint256` to its ASCII `string` hexadecimal representation with fixed length.
     */
    function toHexString(uint256 value, uint256 length) internal pure returns (string memory) {
        bytes memory buffer = new bytes(2 * length + 2);
        buffer[0] = "0";
        buffer[1] = "x";
        for (uint256 i = 2 * length + 1; i > 1; --i) {
            buffer[i] = _HEX_SYMBOLS[value & 0xf];
            value >>= 4;
        }
        require(value == 0, "Strings: hex length insufficient");
        return string(buffer);
    }

    /**
     * @dev Converts an `address` with fixed length of 20 bytes to its not checksummed ASCII `string` hexadecimal representation.
     */
    function toHexString(address addr) internal pure returns (string memory) {
        return toHexString(uint256(uint160(addr)), _ADDRESS_LENGTH);
    }
}


// Dependency file: contracts/universal/Semver.sol

// pragma solidity ^0.8.15;

// import { Strings } from "@openzeppelin/contracts/utils/Strings.sol";

/**
 * @title Semver
 * @notice Semver is a simple contract for managing contract versions.
 */
contract Semver {
    /**
     * @notice Contract version number (major).
     */
    // solhint-disable-next-line var-name-mixedcase
    uint256 private immutable MAJOR_VERSION;

    /**
     * @notice Contract version number (minor).
     */
    // solhint-disable-next-line var-name-mixedcase
    uint256 private immutable MINOR_VERSION;

    /**
     * @notice Contract version number (patch).
     */
    // solhint-disable-next-line var-name-mixedcase
    uint256 private immutable PATCH_VERSION;

    /**
     * @param _major Version number (major).
     * @param _minor Version number (minor).
     * @param _patch Version number (patch).
     */
    constructor(
        uint256 _major,
        uint256 _minor,
        uint256 _patch
    ) {
        MAJOR_VERSION = _major;
        MINOR_VERSION = _minor;
        PATCH_VERSION = _patch;
    }

    /**
     * @notice Returns the full semver contract version.
     *
     * @return Semver contract version as a string.
     */
    function version() public view returns (string memory) {
        return
            string(
                abi.encodePacked(
                    Strings.toString(MAJOR_VERSION),
                    ".",
                    Strings.toString(MINOR_VERSION),
                    ".",
                    Strings.toString(PATCH_VERSION)
                )
            );
    }
}


// Root file: contracts/legacy/DeployerWhitelist.sol

pragma solidity 0.8.15;

// import { Semver } from "contracts/universal/Semver.sol";

/**
 * @custom:legacy
 * @custom:proxied
 * @custom:predeployed 0x4200000000000000000000000000000000000002
 * @title DeployerWhitelist
 * @notice DeployerWhitelist is a legacy contract that was originally used to act as a whitelist of
 *         addresses allowed to the Optimism network. The DeployerWhitelist has since been
 *         disabled, but the code is kept in state for the sake of full backwards compatibility.
 *         As of the Bedrock upgrade, the DeployerWhitelist is completely unused by the Optimism
 *         system and could, in theory, be removed entirely.
 */
contract DeployerWhitelist is Semver {
    /**
     * @notice Address of the owner of this contract. Note that when this address is set to
     *         address(0), the whitelist is disabled.
     */
    address public owner;

    /**
     * @notice Mapping of deployer addresses to boolean whitelist status.
     */
    mapping(address => bool) public whitelist;

    /**
     * @notice Emitted when the owner of this contract changes.
     *
     * @param oldOwner Address of the previous owner.
     * @param newOwner Address of the new owner.
     */
    event OwnerChanged(address oldOwner, address newOwner);

    /**
     * @notice Emitted when the whitelist status of a deployer changes.
     *
     * @param deployer    Address of the deployer.
     * @param whitelisted Boolean indicating whether the deployer is whitelisted.
     */
    event WhitelistStatusChanged(address deployer, bool whitelisted);

    /**
     * @notice Emitted when the whitelist is disabled.
     *
     * @param oldOwner Address of the final owner of the whitelist.
     */
    event WhitelistDisabled(address oldOwner);

    /**
     * @notice Blocks functions to anyone except the contract owner.
     */
    modifier onlyOwner() {
        require(
            msg.sender == owner,
            "DeployerWhitelist: function can only be called by the owner of this contract"
        );
        _;
    }

    /**
     * @custom:semver 0.0.1
     */
    constructor() Semver(0, 0, 1) {}

    /**
     * @notice Adds or removes an address from the deployment whitelist.
     *
     * @param _deployer      Address to update permissions for.
     * @param _isWhitelisted Whether or not the address is whitelisted.
     */
    function setWhitelistedDeployer(address _deployer, bool _isWhitelisted) external onlyOwner {
        whitelist[_deployer] = _isWhitelisted;
        emit WhitelistStatusChanged(_deployer, _isWhitelisted);
    }

    /**
     * @notice Updates the owner of this contract.
     *
     * @param _owner Address of the new owner.
     */
    function setOwner(address _owner) external onlyOwner {
        // Prevent users from setting the whitelist owner to address(0) except via
        // enableArbitraryContractDeployment. If you want to burn the whitelist owner, send it to
        // any other address that doesn't have a corresponding knowable private key.
        require(
            _owner != address(0),
            "DeployerWhitelist: can only be disabled via enableArbitraryContractDeployment"
        );

        emit OwnerChanged(owner, _owner);
        owner = _owner;
    }

    /**
     * @notice Permanently enables arbitrary contract deployment and deletes the owner.
     */
    function enableArbitraryContractDeployment() external onlyOwner {
        emit WhitelistDisabled(owner);
        owner = address(0);
    }

    /**
     * @notice Checks whether an address is allowed to deploy contracts.
     *
     * @param _deployer Address to check.
     *
     * @return Whether or not the address can deploy contracts.
     */
    function isDeployerAllowed(address _deployer) external view returns (bool) {
        return (owner == address(0) || whitelist[_deployer]);
    }
}
