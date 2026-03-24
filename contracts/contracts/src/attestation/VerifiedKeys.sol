// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

/// @title Tracker for verified enclaves and images
/// @notice Contract for tracking enclave keys and enclave image approvals and revocations
abstract contract VerifiedKeys {
    /// @notice Hook to get image family for a given image id
    /// @param _imageId Image id to query
    /// @return bytes32 Family of the image
    function _vkGetImageFamily(bytes32 _imageId) internal view virtual returns (bytes32);

    /// @notice Hook to set image family for a given image id
    /// @param _imageId Image id to modify
    /// @param _family Family to set
    function _vkSetImageFamily(bytes32 _imageId, bytes32 _family) internal virtual;

    /// @notice Hook to get enclave image id for a verified key
    /// @param _key Enclave key to query
    /// @return bytes32 Image id of the key
    function _vkGetEnclaveImage(bytes32 _key) internal view virtual returns (bytes32);

    /// @notice Hook to set enclave image id for a verified key
    /// @param _key Enclave key to modify
    /// @param _imageId Image id to set
    function _vkSetEnclaveImage(bytes32 _key, bytes32 _imageId) internal virtual;

    /// @notice Hook to authorize approval operations
    /// @dev Must revert if not authorized
    function _vkAuthorizeApprove() internal virtual;

    /// @notice Hook to authorize revocation operations
    /// @dev Must revert if not authorized
    function _vkAuthorizeRevoke() internal virtual;

    /// @notice Hook to transform the public key into a format for storage and verification
    /// @dev Intended to be used for e.g. pubkeys to addresses or other similar transformations
    /// @param _pubkey Public key bytes
    /// @return bytes32 Transformed key for storage
    function _vkTransformPubkey(bytes memory _pubkey) internal virtual returns (bytes32);

    /// @notice Default family
    bytes32 public constant DEFAULT_FAMILY = keccak256("DEFAULT_FAMILY");

    /// @notice Error thrown when attempting to modify an image with mismatched family
    error VerifiedKeysFamilyMismatch();

    /// @notice Error thrown when attempting to verify a key with mismatched image
    error VerifiedKeysImageMismatch();

    /// @notice Error thrown when verifying an unregistered or revoked key
    error VerifiedKeysNotVerified();

    /// @notice Emitted when a new image is approved
    /// @param imageId Approved image id
    /// @param family Family of the image
    event VerifiedKeysApproved(bytes32 indexed imageId, bytes32 indexed family);

    /// @notice Emitted when an image is revoked
    /// @param imageId Revoked image id
    /// @param family Family of the image
    event VerifiedKeysRevoked(bytes32 indexed imageId, bytes32 indexed family);

    /// @notice Emitted when a public key is verified
    /// @param key Transformed key
    /// @param imageId Image id of the key
    /// @param pubkey Public key bytes
    event VerifiedKeysVerified(bytes32 indexed key, bytes32 indexed imageId, bytes pubkey);

    /// @notice Initializes contract with an initial approved image
    /// @param _imageId Image id to approve, must be nonzero
    /// @param _family Family of the initial image, must be nonzero
    constructor(bytes32 _imageId, bytes32 _family) {
        _approveImage(_imageId, _family);
    }

    /// @notice Internal function to approve a new image
    /// @param _imageId Image id to approve, must be nonzero
    /// @param _family Family to associate with the image, must be nonzero
    /// @return bool True if approval was successful, false if already approved
    function _approveImage(bytes32 _imageId, bytes32 _family) internal returns (bool) {
        bytes32 _currentFamily = _vkGetImageFamily(_imageId);
        if (_currentFamily != bytes32(0)) {
            require(_currentFamily == _family, VerifiedKeysFamilyMismatch());

            return false;
        }

        _vkSetImageFamily(_imageId, _family);
        emit VerifiedKeysApproved(_imageId, _family);

        return true;
    }

    /// @notice Internal function to revoke an approved image
    /// @param _imageId Image id to revoke
    /// @return bool True if revocation was successful, false if not found
    function _revokeImage(bytes32 _imageId) internal returns (bool) {
        bytes32 _currentFamily = _vkGetImageFamily(_imageId);
        if (_currentFamily == bytes32(0)) return false;

        _vkSetImageFamily(_imageId, bytes32(0));
        emit VerifiedKeysRevoked(_imageId, _currentFamily);

        return true;
    }

    /// @notice Approves a new image with authorization check
    /// @dev Calls internal _approveImage after authorization
    /// @param _imageId Image id to approve, must be nonzero
    /// @param _family Family to associate with the image, must be nonzero
    /// @return bool True if approval was successful, false if already approved
    function approveImage(bytes32 _imageId, bytes32 _family) external returns (bool) {
        _vkAuthorizeApprove();
        return _approveImage(_imageId, _family);
    }

    /// @notice Revokes an approved image with authorization check
    /// @dev Calls internal _revokeImage after authorization
    /// @param _imageId Image id to revoke
    /// @return bool True if revocation was successful, false if not found
    function revokeImage(bytes32 _imageId) external returns (bool) {
        _vkAuthorizeRevoke();
        return _revokeImage(_imageId);
    }

    /// @notice Internal function to verify a public key
    /// @param _enclavePubkey Public key bytes to verify
    /// @param _imageId Image id to associate with the key, must be nonzero
    /// @return bool True if verification was successful, false if key is already verified
    function _setKeyVerified(bytes memory _enclavePubkey, bytes32 _imageId) internal returns (bool) {
        bytes32 _key = _vkTransformPubkey(_enclavePubkey);
        bytes32 _currentImageId = _vkGetEnclaveImage(_key);
        if (_currentImageId != bytes32(0)) {
            require(_currentImageId == _imageId, VerifiedKeysImageMismatch());

            return false;
        }

        _vkSetEnclaveImage(_key, _imageId);
        emit VerifiedKeysVerified(_key, _imageId, _enclavePubkey);

        return true;
    }

    /// @notice Ensures a key is verified
    /// @dev Checks both key and image status
    /// @param _key Transformed key to verify
    /// @param _expectedFamily Family the key should belong to
    function _ensureKeyVerified(bytes32 _key, bytes32 _expectedFamily) internal view {
        bytes32 _imageId = _vkGetEnclaveImage(_key);
        require(_imageId != bytes32(0), VerifiedKeysNotVerified());
        bytes32 _family = _vkGetImageFamily(_imageId);
        // check family
        require(_expectedFamily == _family, VerifiedKeysNotVerified());
    }

    /// @notice Ensures a key is verified
    /// @dev Calls _ensureKeyVerified with DEFAULT_FAMILY
    /// @param _key Transformed key to verify
    function _ensureKeyVerified(bytes32 _key) internal view {
        _ensureKeyVerified(_key, DEFAULT_FAMILY);
    }
}

/// @title Default Verified Keys Implementation
/// @notice Concrete implementation of VerifiedKeys with storage mappings
abstract contract VerifiedKeysDefault is VerifiedKeys {
    /// @notice Mapping of image IDs to their associated families
    mapping(bytes32 => bytes32) public images;

    /// @notice Mapping of transformed public key hashes to image IDs
    mapping(bytes32 => bytes32) public keys;

    /// @inheritdoc VerifiedKeys
    function _vkGetImageFamily(bytes32 _imageId) internal view virtual override returns (bytes32) {
        return images[_imageId];
    }

    /// @inheritdoc VerifiedKeys
    function _vkSetImageFamily(bytes32 _imageId, bytes32 _family) internal virtual override {
        images[_imageId] = _family;
    }

    /// @inheritdoc VerifiedKeys
    function _vkGetEnclaveImage(bytes32 _key) internal view virtual override returns (bytes32) {
        return keys[_key];
    }

    /// @inheritdoc VerifiedKeys
    function _vkSetEnclaveImage(bytes32 _key, bytes32 _imageId) internal virtual override {
        keys[_key] = _imageId;
    }
}
