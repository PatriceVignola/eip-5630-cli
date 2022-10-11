import fs from "fs";
import path from "path";
import secp256k1 from "secp256k1";
import keccak256 from "keccak256";
import { encrypt } from "eciesjs";
import { eth_getEncryptionPublicKey, eth_decrypt } from "eip-5630";

import readlineSync from "readline-sync";

enum State {
  None,
  Encrypting,
  Decrypting,
}

function showAvailableCommands() {
  console.log("Available commands:");
  console.log("    encrypt <file>");
  console.log("    decrypt <file>");
}

function isValidPrivateKey(privateKey: string) {
  return (
    privateKey.length === 64 &&
    secp256k1.privateKeyVerify(Buffer.from(privateKey, "hex"))
  );
}

function isAnswered(confirmation: string): boolean {
  return confirmation === "y" || confirmation === "n" || confirmation === "";
}

function publicKeyToAddress(publicKey: Uint8Array): string {
  // Remove the first byte (0x04), which is the type byte for an Ethereum
  // address
  const address =
    "0x" +
    keccak256(Buffer.from(publicKey.slice(1)))
      .subarray(-20)
      .toString("hex");
  return address;
}

if (process.argv.length < 3) {
  showAvailableCommands();
  process.exit(0);
}

const files = [];
let state = State.None;
for (const arg of process.argv.slice(2)) {
  switch (state) {
    case State.None:
      if (arg === "encrypt") {
        state = State.Encrypting;
      } else if (arg === "decrypt") {
        state = State.Decrypting;
      } else {
        console.error(`"${arg}" is not a valid command.`);
        showAvailableCommands();
        process.exit(1);
      }
      break;
    case State.Decrypting:
      if (!arg.endsWith(".eip5630")) {
        console.error(
          `"${arg}" is not a valid encrypted file. Encrypted files must end ` +
            `with the ".eip5630" extension.`
        );
        process.exit(1);
      }

    case State.Encrypting:
      const fullFilePath = path.resolve(arg);
      if (!fs.existsSync(fullFilePath)) {
        console.error(`"${arg}" is not a valid file path.`);
        process.exit(1);
      }
      files.push(fullFilePath);
      break;
  }
}

let privateKey = "0";
while (!isValidPrivateKey(privateKey)) {
  privateKey = readlineSync.question(
    "Enter your private key (press enter to abort): ",
    {
      hideEchoBack: true,
    }
  );

  if (privateKey === "") {
    process.exit(1);
  }

  if (!isValidPrivateKey(privateKey)) {
    console.error(`You entered an invalid private key.`);
  }
}

const publicKey = secp256k1.publicKeyCreate(
  Buffer.from(privateKey, "hex"),
  false
);

const address = publicKeyToAddress(publicKey);

for (const filePath of files) {
  switch (state) {
    case State.Encrypting:
      {
        console.log(`Encrypting all files for ${address}:`);
        const encryptedFilePath = filePath + ".eip5630";
        console.log(`    ${filePath} -> ${encryptedFilePath}`);
        const file = fs.readFileSync(filePath);
        const encryptionKey = eth_getEncryptionPublicKey(privateKey);
        const encryptedFile = encrypt(encryptionKey, file);
        fs.writeFileSync(encryptedFilePath, encryptedFile);
      }
      break;
    case State.Decrypting:
      {
        console.log(`Decrypting all files for ${address}:`);
        const decryptedFilePath = filePath.split(".").slice(0, -1).join(".");
        console.log(`    ${filePath} -> ${decryptedFilePath}`);
        const file = fs.readFileSync(filePath);
        const decryptedFile = eth_decrypt(privateKey, file);
        fs.writeFileSync(decryptedFilePath, decryptedFile);
      }
      break;
  }
}
