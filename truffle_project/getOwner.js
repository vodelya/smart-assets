const { Web3 } = require('web3');
const fs = require('fs');
const path = require('path');

// Replace with your network endpoint
const network = 'http://127.0.0.1:8545';
const web3 = new Web3(network);
// Replace with your contract's ABI and address
const contractABI = JSON.parse(fs.readFileSync(path.resolve(__dirname, './build/contracts/AssetManager.json'), 'utf-8')).abi;
const contractAddress = '0xBca0fDc68d9b21b5bfB16D784389807017B2bbbc'; // Replace with your contract address

// Create a new contract instance
const contract = new web3.eth.Contract(contractABI, contractAddress);

async function getOwner() {
    try {
        const owner = await contract.methods.owner().call();
        console.log('Contract Owner:', owner);
    } catch (error) {
        console.error('Error fetching owner:', error);
    }
}

getOwner();
