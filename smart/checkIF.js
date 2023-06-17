const { ethers } = require('ethers');
const fs = require('fs');
const { exit, argv } = require('process');
const key = require("../vp.json")
const abi = require("./abi.json")

async function GetOwnerOFVault(con, vaultId) {
  // Create a new Web3 instance
  //const web3 = new Web3('https://filecoin-calibration.chainup.net/rpc/v1');
  const provider = new ethers.WebSocketProvider('wss://wss.calibration.node.glif.io/apigw/lotus/rpc/v0');
  //const signer = provider.getSigner();
  var nextcon 
  if(con != "")
  {
    nextcon = con
  }else if (key.contract != ""){
    nextcon = key.contract
  }else if(con == "" && key.contract == "")
  {
    console.log({'"address"':'"'+ '"'}); 
    exit();
  }

  const contract2 = new ethers.Contract(nextcon, abi, provider);

  const vaultData = await contract2.vaults(vaultId);
  // Extract the individual fields from the returned data
  const { owner, rentEndTime, lastExecution } = vaultData;
  // Print the deployed contract address
  console.log({'"address"':'"'+ owner + '"'});
}

const args = process.argv.slice(2); // Exclude the first two elements

GetOwnerOFVault(args[0], args[1]).catch((err) => {
  console.error('Failed to deploy contract:', err);
}).then(()=>{
    exit();
})
