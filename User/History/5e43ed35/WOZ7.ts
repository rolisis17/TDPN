import "dotenv/config";
import { getKeypairFromEnvironment, getExplorerLink, getKeypairFromFile } from "@solana-developers/helpers";
import {
    Connection,
    clusterApiUrl,
    PublicKey,
    Transaction,
    sendAndConfirmTransaction,
} from "@solana/web3.js";
import { createCreateMetadataAccountV3Instruction, TOKEN_METADATA_PROGRAM_ID,} from "@metaplex-foundation/mpl-token-metadata";
import {
    createUpdateMetadataAccountV2Instruction,
    PROGRAM_ID as TOKEN_METADATA_PROGRAM_ID,
  } from "@metaplex-foundation/mpl-token-metadata";
import { createMint } from "@solana/spl-token";

const user = await getKeypairFromFile("/home/stella/.config/solana/id.json");
const connection = new Connection(clusterApiUrl("devnet"), "confirmed");

console.log(`🔑 We've loaded our keypair securely, using an env file! Our public key is: ${user.publicKey.toBase58()}`);

const tokenMint = await createMint(connection, user, user.publicKey, user.publicKey, 5);

const link = getExplorerLink("address", tokenMint.toString(), "devnet");

console.log(`✅ Finished! Created token mint: ${link}\nToken Address: ${tokenMint.toBase58()}`);

// const TOKEN_METADATA_PROGRAM_ID = new PublicKey("metaqbxxUerdq28cj1RbAWkYQm3ybzjb6a8bt518x1s");
console.log(TOKEN_METADATA_PROGRAM_ID);

// Substitute in your token mint account from explorer
const tokenMintAccount = tokenMint;

const metadataData = {
    name: "ShakeThat",
    symbol: "SHAKE",
    // Paste in your JSON file Arweave link using Metaplex standard for off-chain data
    uri: "https://copper-labour-antelope-826.mypinata.cloud/ipfs/QmSth9wVbCfUsqzcF3jgqYshjoTj6E5NTL9uR1ZKSMRk7H",
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

const transaction = new Transaction();

const createMetadataAccountInstruction =
    createCreateMetadataAccountV3Instruction(
        {
            metadata: metadataPDA,
            mint: tokenMintAccount,
            mintAuthority: user.publicKey,
            payer: user.publicKey,
            updateAuthority: user.publicKey,
        },
        {
            createMetadataAccountArgsV3: {
                collectionDetails: null,
                data: metadataData,
                isMutable: true,
            },
        }
    );

transaction.add(createMetadataAccountInstruction);

const transactionSignature = await sendAndConfirmTransaction(
    connection,
    transaction,
    [user]
);

const transactionLink = getExplorerLink(
    "transaction",
    transactionSignature,
    "devnet"
);

console.log(`✅ Transaction confirmed, explorer link is: ${transactionLink}!`);

const tokenMintLink = getExplorerLink(
    "address",
    tokenMintAccount.toString(),
    "devnet"
);

console.log(`✅ Look at the token mint again: ${tokenMintLink}!`);
