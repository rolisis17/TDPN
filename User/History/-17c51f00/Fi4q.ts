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

const TOKEN_METADATA_PROGRAM_ID = new PublicKey("metaqbxxUerdq28cj1RbAWkYQm3ybzjb6a8bt518x1s");
console.log(TOKEN_METADATA_PROGRAM_ID);

// Substitute in your token mint account from explorer
const tokenMintAccount = new PublicKey("FimqimMtXLFef1B6Vw6d3LKhcduwDBMNqcPwkbG4kBwQ");

const metadataData = {
    name: "ShakeThat",
    symbol: "SHAKE",
    // Paste in your JSON file Arweave link using Metaplex standard for off-chain data
    uri: "Qmeg7XTHf7eucVb449zedcWwX516WqbQD71HUf3Bv3siv6",
    sellerFeeBasisPoints: 0,
    creators: null,
    collection: null,
    uses: null,
};

const metadataPDAAndBump = PublicKey.findProgramAddressSync(
    [
        Buffer.from("metadata"),
        TOKEN_METADATA_PROGRAM_ID.toBuffer(),
        tokenMintAccount.toBuffer(),
    ],
    TOKEN_METADATA_PROGRAM_ID
);

const metadataPDA = metadataPDAAndBump[0];
