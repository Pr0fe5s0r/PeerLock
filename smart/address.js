const { ethers } = require('ethers');
const key = require("../key.json")

async function signAndExtractAddress(value, privateKey) {
  // Create an Ethereum wallet instance using the private key
  const wallet = new ethers.Wallet(privateKey);

  // Sign the value
  const signature = await wallet.signMessage(value);

  return signature;
}

async function GetTheAddress(value, signature)
{
     // Recover the signer's address from the signature
  const signer = ethers.verifyMessage(value, signature);
  const address = ethers.getAddress(signer);

  return address
}


const args = process.argv.slice(2); // Exclude the first two elements

// Check if vaultId argument is provided
if (args.length === 0) {
  console.log('Please provide the vaultId argument');
  process.exit(1);
}

if(args[0] == 's')
{
    signAndExtractAddress(args[1], key.privateKey)
    .then((address) => {
        console.log({'"address"':'"'+address + '"'});
    })
    .catch((error) => {
        console.error(error);
    });
}else{
    GetTheAddress(args[1], args[2])
    .then((address) => {
        console.log({'"address"':'"'+address + '"'});
    })
    .catch((error) => {
        console.error(error);
    });
}
