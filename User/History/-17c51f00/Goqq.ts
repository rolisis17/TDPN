import "dotenv/config";
import { getKeypairFromEnvironment, getExplorerLink } from "@solana-developers/helpers";
import {
    Connection,
    clusterApiUrl,
    PublicKey,
    Transaction,
    sendAndConfirmTransaction,
} from "@solana/web3.js";
import { createCreateMetadataAccountV3Instruction } from "@metaplex-foundation/mpl-token-metadata";

const user = getKeypairFromEnvironment("SECRET_KEY");
const connection = new Connection(clusterApiUrl("devnet"), "confirmed");

console.log(`🔑 We've loaded our keypair securely, using an env file! Our public key is: ${user.publicKey.toBase58()}`);