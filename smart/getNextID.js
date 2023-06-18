const { ethers } = require('ethers');
const fs = require('fs');
const { exit, argv } = require('process');
const key = require("../vp.json")
const abi = require("./abi.json")

async function GetLastID(con) {
  // Create a new Web3 instance
  //const web3 = new Web3('https://filecoin-calibration.chainup.net/rpc/v1');
  const provider = new ethers.WebSocketProvider('wss://wss.calibration.node.glif.io/apigw/lotus/rpc/v0');
  //const signer = provider.getSigner();
  var nextcon 
  if(con != undefined)
  {
    nextcon = con
  }else if (key.contract != undefined){
    nextcon = key.contract
  }
  
  if(con == "" && key.contract == "")
  {
    console.log({'"vault_id"':'"'+ '"'}); 
    exit();
  }
  
  const contract2 = new ethers.Contract(nextcon, abi, provider);

  // Print the deployed contract address
  console.log({'"vault_id"':'"'+await contract2.getNextVaultID() + '"', '"contract"':'"'+nextcon + '"'});
}

const args = process.argv.slice(2); // Exclude the first two elements

GetLastID(args[0]).catch((err) => {
  console.error('Failed to deploy contract:', err);
}).then(()=>{
    exit();
})
