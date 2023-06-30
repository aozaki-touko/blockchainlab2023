const Contract = artifacts.require("Voting");
module.exports = function(deployer) {
  let aliceAccount = '0xca21bde509810582dd0f2f36f2a51817b4f2c3c60c377a51e0cbb6ef8e7597f1';
  let bobAccount = '0x6f8a1f64e38f55a22e76e9d41d14dc3ed9bdf6e098e4066e4a72c21eb7d0bba9';
  let johnAccount = '0xa9e7d01f428aa9e3eaa45a1bb8ef235445dc20a45e3e8cc10cf7891eab4dbf2c';
  const addr = ['0xca21bde509810582dd0f2f36f2a51817b4f2c3c60c377a51e0cbb6ef8e7597f1', '0x6f8a1f64e38f55a22e76e9d41d14dc3ed9bdf6e098e4066e4a72c21eb7d0bba9', '0xa9e7d01f428aa9e3eaa45a1bb8ef235445dc20a45e3e8cc10cf7891eab4dbf2c']
  deployer.deploy(Contract);
};
