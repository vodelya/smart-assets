module.exports = {
  networks: {
    quorum: {
      host: "127.0.0.1",
      port: 8545,
      network_id: "1337",
      gasPrice: 0
    }
  },
  compilers: {
    solc: {
      version: "0.8.1",  // Match the version required by your contract
    }
  }
};
