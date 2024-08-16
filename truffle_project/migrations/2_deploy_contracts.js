const AssetManager = artifacts.require("AssetManager");

module.exports = async function (deployer, network, accounts) {
    // Deploy the AssetManager contract
    await deployer.deploy(AssetManager);
    const assetManager = await AssetManager.deployed();

    // Address used to issue the assets (must be the same due to contract requirements)
    const issuingAddress = "0xc9c913c8c3c1cd416d80a0abf475db2062f161f6";

    // Array to store the time taken for each transaction
    let issuanceTimes = [];

    // File path to save the output
    const filePath = './issuance_times.txt';

    // Write the header to the file
    const fs = require('fs');
    fs.writeFileSync(filePath, 'Transaction,Asset ID,Time (ms)\n');

    // Issue 1000 assets with both Non-transferable and Functional categories, and measure issuance time
    for (let i = 0; i < 10; i++) {
        const assetId = `Asset${i + 1}`;
        const assetType = `Type${i + 1}`;
        const categories = ["Non-Transferable", "Functional"]; // Both categories
        const issuerType = `IssuerType${i + 1}`;
        const startTime = process.hrtime(); // Start the timer

        try {
            await assetManager.issueAsset(
                issuingAddress,
                assetId,
                `Issuer${i + 1}`,
                assetType,
                categories, // Pass the array of categories
                1, // Active status
                issuerType,
                false, // Non-transferable
                true,  // Functional
                { from: issuingAddress }
            );
        } catch (error) {
            console.log(`Error issuing ${assetId}:`, error.message);
        }

        const endTime = process.hrtime(startTime); // End the timer
        const transactionTimeInMilliseconds = (endTime[0] * 1000 + endTime[1] / 1e6).toFixed(3); // Convert to milliseconds
        issuanceTimes.push({
            transaction: i + 1,
            assetId,
            time: transactionTimeInMilliseconds,
        });

        // Log to the console (optional)
        console.log(`Issuance ${i + 1} for ${assetId} took ${transactionTimeInMilliseconds} ms`);

        // Write to the file
        fs.appendFileSync(filePath, `${i + 1},${assetId},${transactionTimeInMilliseconds}\n`);
    }

    // Output the results in a tabular format (optional)
    console.log("Issuance Times:");
    console.table(issuanceTimes);
};
