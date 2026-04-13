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
  
  (async () => {
    // Connect to the Solana cluster
    const connection = new Connection(clusterApiUrl("devnet"), "confirmed");
  
    // Replace with your mint public key
    const mintPublicKey = new PublicKey("YourMintAccountPublicKey");
  
    // Replace with the keypair of the update authority
    const updateAuthority = Keypair.generate(); // Replace with your real keypair
  
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
      name: "Updated Token Name",
      symbol: "UPDT",
      uri: "https://new-metadata-uri-link.json",
      sellerFeeBasisPoints: 500, // Royalties in basis points (5%)
      creators: null, // Optional: Define creators if needed
      collection: null, // Optional: Link to a collection if applicable
      uses: null, // Optional: Usage info
    };
  
    // Create the update instruction
    const updateInstruction = createUpdateMetadataAccountV2Instruction(
      {
        metadata: metadataAccount,
        updateAuthority: updateAuthority.publicKey,
      },
      {
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
  