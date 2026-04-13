import {
    Connection,
    PublicKey,
    Keypair,
    Transaction,
    clusterApiUrl,
  } from "@solana/web3.js";
  import {
    createUpdateMetadataAccountV2Instruction,
    DataV2,
  } from "@metaplex-foundation/mpl-token-metadata";
import { getKeypairFromEnvironment } from "@solana-developers/helpers";
  
  (async () => {
    // Connect to the Solana cluster
    const connection = new Connection(clusterApiUrl("devnet"), "confirmed");
  
    // Replace with your mint public key
    const mintPublicKey = new PublicKey("FimqimMtXLFef1B6Vw6d3LKhcduwDBMNqcPwkbG4kBwQ");
  
    // Replace with the keypair of the update authority
    const updateAuthority = getKeypairFromEnvironment("SECRET_KEY"); // Replace with your real keypair
  
    // Derive the metadata account PDA
    const [metadataAccount] = await PublicKey.findProgramAddress(
      [
        Buffer.from("metadata"),
        PublicKey.default.toBuffer(), // Token Metadata program ID
        mintPublicKey.toBuffer(),
      ],
      new PublicKey("metaqbxxUerdq28cj1RbAWkYQm3ybzjb6a8bt518x1s")
    );
  
    console.log("Metadata Account Address:", metadataAccount.toBase58());
  
    // Define new metadata
    const newMetadata: DataV2 = {
      name: "ShakeThat",
      symbol: "SHAKE",
      // Paste in your JSON file Arweave link using Metaplex standard for off-chain data
      uri: "Qmeg7XTHf7eucVb449zedcWwX516WqbQD71HUf3Bv3siv6",
      sellerFeeBasisPoints: 0, // Royalties in basis points (0%)
      creators: null, // Optional: Define creators if needed
      collection: null, // Optional: Link to a collection if applicable
      uses: null, // Optional: Usage info
    };[229,99,163,165,235,99,147,253,234,106,60,202,68,84,30,42,92,126,248,153,57,205,115,207,162,15,92,125,224,245,84,57,6,177,88,254,31,26,197,180,170,21,203,223,104,6,205,6,206,45,164,82,94,80,115,228,126,136,76,51,61,90,17,160]
  
    // Create the update instruction
    const updateInstruction = createUpdateMetadataAccountV2Instruction(
      {
        metadata: metadataAccount,
        updateAuthority: updateAuthority.publicKey,
      },
      {[229,99,163,165,235,99,147,253,234,106,60,202,68,84,30,42,92,126,248,153,57,205,115,207,162,15,92,125,224,245,84,57,6,177,88,254,31,26,197,180,170,21,203,223,104,6,205,6,206,45,164,82,94,80,115,228,126,136,76,51,61,90,17,160]
        data: newMetadata,
        isMutable: true,
        primarySaleHappened: true, // Set if the primary sale has already occurred
      }
    );
  
    // Send the transaction
    const transaction = new Transaction().add(updateInstruction);
    const signature = await connection.sendTransaction(transaction, [updateAuthority]);
  
    console.log("Transaction Signature:", signature);
  })();
  