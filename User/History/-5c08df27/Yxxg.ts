import { createMint } from "@solana/spl-token";
import "dotenv/config";
import { getKeypairFromEnvironment, getExplorerLink, getKeypairFromFile } from "@solana-developers/helpers";
import { Connection, clusterApiUrl } from "@solana/web3.js";

const connection = new Connection(clusterApiUrl('devnet'), "confirmed");

// Load the secret key from the env file and generate the keypair
const user = getKeypairFromFile("SECRET_KEY");

console.log(`🔑 Loaded our keypair securely, Our public key is: ${user.publicKey.toBase58()}`);

const tokenMint = await createMint(connection, user, user.publicKey, user.publicKey, 5);

const link = getExplorerLink("address", tokenMint.toString(), "devnet");

console.log(`✅ Finished! Created token mint: ${link}`);