// Usage: npm run start -- encrypt --chunk-size <chunk_size_in_bytes> <file1> <file2> ...

import fs from "fs";
import path from "path";
import secp256k1 from "secp256k1";
import keccak256 from "keccak256";
import { encrypt } from "eciesjs";
import { eth_getEncryptionPublicKey, eth_decrypt } from "eip-5630";
import { readChunk } from "read-chunk";

import readlineSync from "readline-sync";

enum State {
  None,
  Encrypting,
  Decrypting,
  ChoosingChunkSize,
}

function showAvailableCommands() {
  console.log("Available commands:");
  console.log("    encrypt [--chunk-size <size_in_bytes>] <file1> <file2> ...");
  console.log("    decrypt [--chunk-size <size_in_bytes>] <file1> <file2> ...");
}

function isValidPrivateKey(privateKey: string) {
  return (
    privateKey.length === 64 &&
    secp256k1.privateKeyVerify(Buffer.from(privateKey, "hex"))
  );
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

async function appendBuffersToStream(
  stream: fs.WriteStream,
  encryptedBuffer: Buffer
): Promise<void> {
  return new Promise<void>((resolve, reject) => {
    stream.write(encryptedBuffer, (error) => {
      if (error !== undefined && error !== null) {
        reject(error);
      } else {
        resolve();
      }
    });
  });
}

if (process.argv.length < 3) {
  showAvailableCommands();
  process.exit(0);
}

let chunkSize = 0;

const files = [];
let prevState = State.None;
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
      if (arg == "--chunk-size") {
        prevState = state;
        state = State.ChoosingChunkSize;
      } else {
        if (!arg.endsWith(".eip5630")) {
          console.error(
            `"${arg}" is not a valid encrypted file. Encrypted files must ` +
              `end with the ".eip5630" extension.`
          );
          process.exit(1);
        }

        const fullFilePath = path.resolve(arg);
        if (!fs.existsSync(fullFilePath)) {
          console.error(`"${arg}" is not a valid file path.`);
          process.exit(1);
        }
        files.push(fullFilePath);
      }
      break;
    case State.Encrypting:
      if (arg == "--chunk-size") {
        prevState = state;
        state = State.ChoosingChunkSize;
      } else {
        const fullFilePath = path.resolve(arg);
        if (!fs.existsSync(fullFilePath)) {
          console.error(`"${arg}" is not a valid file path.`);
          process.exit(1);
        }
        files.push(fullFilePath);
      }

      break;
    case State.ChoosingChunkSize:
      chunkSize = Number(arg);
      state = prevState;
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

async function readStreamsByChunks(
  filePath: string,
  chunkSize: number,
  processorKey: string,
  postProcessor: (encryptionKey: string, inputBuffer: Buffer) => Buffer
): Promise<Buffer[]> {
  const stream = fs.createReadStream(filePath);

  const encryptedBuffers: Buffer[] = [];

  const fileInfo = fs.statSync(filePath);
  const numChunks = fileInfo.size / chunkSize;
  console.log(`numChunks: ${numChunks}`);

  for (let i = 0; i < numChunks; ++i) {
    console.log(`reading chunk ${i}...`);
    const currentBuffer = await readChunk(filePath, {
      length: chunkSize,
      startPosition: chunkSize * i,
    });

    const encryptedBuffer = postProcessor(processorKey, currentBuffer);
    encryptedBuffers.push(encryptedBuffer);
  }

  return encryptedBuffers;
}

files.forEach(async (filePath) => {
  const currentChunkSize = chunkSize == 0 ? 2e9 : chunkSize;

  switch (state) {
    case State.Encrypting:
      {
        console.log(`Encrypting all files for ${address}:`);

        const encryptedFilePath =
          filePath + "." + currentChunkSize + ".eip5630";
        console.log(`    ${filePath} -> ${encryptedFilePath}`);

        const encryptionKey = eth_getEncryptionPublicKey(privateKey);

        const encryptedBuffers = await readStreamsByChunks(
          filePath,
          currentChunkSize,
          encryptionKey,
          encrypt
        );

        const encryptedStream = fs.createWriteStream(encryptedFilePath);
        encryptedBuffers.forEach(async (encryptedBuffer) => {
          await appendBuffersToStream(encryptedStream, encryptedBuffer);
        });
      }
      break;
    case State.Decrypting:
      {
        console.log(`Decrypting all files for ${address}:`);
        const decryptedFilePath = filePath.split(".").slice(0, -2).join(".");
        console.log(`    ${filePath} -> ${decryptedFilePath}`);

        // The cypher seems to append 97 bytes per chunk
        const cipherLen = currentChunkSize + 97;

        const decryptedBuffers = await readStreamsByChunks(
          filePath,
          cipherLen,
          privateKey,
          eth_decrypt
        );

        const decryptedStream = fs.createWriteStream(decryptedFilePath);
        decryptedBuffers.forEach(async (decryptedBuffer) => {
          await appendBuffersToStream(decryptedStream, decryptedBuffer);
        });
      }
      break;
  }
});
