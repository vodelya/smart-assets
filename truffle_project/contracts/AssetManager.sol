// SPDX-License-Identifier: MIT
pragma solidity ^0.8.1;

import "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

contract AssetManager is ERC721, Ownable {
    uint256 public nextTokenId;

    enum Status { Inactive, Active }

    struct Asset {
        string assetIdentifier;
        string assetIssuer;
        string assetType;
        string[] categories; // Array to hold multiple categories
        Status status;
        string issuerType;
        bool isTransferable;
        bool isFunctional;
    }

    mapping(uint256 => Asset) public assets;
    mapping(address => mapping(string => uint256)) public activeFunctionalAssets;

    constructor() ERC721("AssetManager", "ASM") Ownable() {}

    // Function to issue a new asset
    function issueAsset(
        address to,
        string memory assetIdentifier,
        string memory assetIssuer,
        string memory assetType,
        string[] memory categories,
        Status status,
        string memory issuerType,
        bool isTransferable,
        bool isFunctional
    ) external onlyOwner {
        // Check if the asset has the "Functional" category and is active
        if (hasCategory(categories, "Functional") && status == Status.Active) {
            require(activeFunctionalAssets[to][assetType] == 0, "Owner already has an active functional asset of this type");
        }

        uint256 tokenId = nextTokenId;
        nextTokenId++;

        assets[tokenId] = Asset({
            assetIdentifier: assetIdentifier,
            assetIssuer: assetIssuer,
            assetType: assetType,
            categories: categories, // Assign the array of categories
            status: status,
            issuerType: issuerType,
            isTransferable: isTransferable,
            isFunctional: isFunctional
        });

        _safeMint(to, tokenId);

        if (hasCategory(categories, "Functional") && status == Status.Active) {
            activeFunctionalAssets[to][assetType] = tokenId;
        }
    }

    function updateAssetStatus(uint256 tokenId, Status status) external {
        require(ownerOf(tokenId) == msg.sender, "Only the owner can update the status");

        Asset storage asset = assets[tokenId];
        string memory assetType = asset.assetType;

        if (hasCategory(asset.categories, "Functional")) {
            if (status == Status.Active) {
                require(activeFunctionalAssets[msg.sender][assetType] == 0, "Owner already has an active functional asset of this type");
                activeFunctionalAssets[msg.sender][assetType] = tokenId;
            } else {
                if (asset.status == Status.Active) {
                    activeFunctionalAssets[msg.sender][assetType] = 0;
                }
            }
        }

        asset.status = status;
    }

    function _transfer(
        address from,
        address to,
        uint256 tokenId
    ) internal virtual override {
        Asset memory asset = assets[tokenId];
        require(asset.isTransferable, "This asset is non-transferable.");
        require(!hasCategory(asset.categories, "Non-Transferable"), "Soulbound token: transfer not allowed for Non-Transferable category");

        super._transfer(from, to, tokenId);

        if (hasCategory(asset.categories, "Functional") && asset.status == Status.Active) {
            activeFunctionalAssets[from][asset.assetType] = 0;
            activeFunctionalAssets[to][asset.assetType] = tokenId;
        }
    }

    function safeTransferFrom(
        address from,
        address to,
        uint256 tokenId,
        bytes memory _data
    ) public virtual override {
        Asset memory asset = assets[tokenId];
        require(asset.isTransferable, "This asset is non-transferable.");
        require(!hasCategory(asset.categories, "Non-Transferable"), "Soulbound token: transfer not allowed for Non-Transferable category");

        super.safeTransferFrom(from, to, tokenId, _data);
    }

    function safeTransferFrom(
        address from,
        address to,
        uint256 tokenId
    ) public virtual override {
        Asset memory asset = assets[tokenId];
        require(asset.isTransferable, "This asset is non-transferable.");
        require(!hasCategory(asset.categories, "Non-Transferable"), "Soulbound token: transfer not allowed for Non-Transferable category");

        super.safeTransferFrom(from, to, tokenId);
    }

    function transferFrom(
        address from,
        address to,
        uint256 tokenId
    ) public virtual override {
        Asset memory asset = assets[tokenId];
        require(asset.isTransferable, "This asset is non-transferable.");
        require(!hasCategory(asset.categories, "Non-Transferable"), "Soulbound token: transfer not allowed for Non-Transferable category");

        super.transferFrom(from, to, tokenId);
    }

    function _burn(uint256 tokenId) internal virtual override {
        address owner = ownerOf(tokenId);
        Asset memory asset = assets[tokenId];

        super._burn(tokenId);

        if (hasCategory(asset.categories, "Functional") && asset.status == Status.Active) {
            activeFunctionalAssets[owner][asset.assetType] = 0;
        }
    }

    // Utility function to check if an asset has a specific category
    function hasCategory(string[] memory categories, string memory category) internal pure returns (bool) {
        for (uint256 i = 0; i < categories.length; i++) {
            if (keccak256(bytes(categories[i])) == keccak256(bytes(category))) {
                return true;
            }
        }
        return false;
    }
}
