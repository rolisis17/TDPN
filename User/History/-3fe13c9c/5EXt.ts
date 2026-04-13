import {
  clusterApiUrl,
  Connection,
  Keypair,
  sendAndConfirmTransaction,
  SystemProgram,
  Transaction,
  PublicKey,
} from "@solana/web3.js";
import {
  createInitializeMintInstruction,
  TOKEN_PROGRAM_ID,
  MINT_SIZE,
  getMinimumBalanceForRentExemptMint,
  createMint,
  getMint,
  createAssociatedTokenAccount,
  createMintToCheckedInstruction,
  mintToChecked,
  createAssociatedTokenAccountInstruction,
  createTransferCheckedInstruction,
  transferChecked,
} from "@solana/spl-token";
import bs58 from "bs58";
import { getKeypairFromFile } from "@solana-developers/helpers";
 
(async () => {
  // connection
  const connection = new Connection(clusterApiUrl("devnet"), "confirmed");
  const recentBlockhash = await connection.getLatestBlockhash();

  getKeypairFromFile
 
  // 5YNmS1R9nNSCDzb5a7mMJ1dwK9uHeAAF4CmPEwKgVWr8
  const feePayer = Keypair.fromSecretKey(
    bs58.decode(
      "588FU4PktJWfGfxtzpAAXywSNt74AvtroVzGfKkVN1LwRuvHwKGr851uH8czM5qm4iqLbs1kKoMKtMJG4ATR7Ld2",
    ),
  );
 
  // G2FAbFQPFa5qKXCetoFZQEvF9BVvCKbvUZvodpVidnoY
  const alice = Keypair.fromSecretKey(
    bs58.decode(
      "4NMwxzmYj2uvHuq8xoqhY8RXg63KSVJM1DXkpbmkUY7YQWuoyQgFnnzn6yo3CMnqZasnNPNuAT2TLwQsCaKkUddp",
    ),
  );
 
  // 1) use build-in function
  let mintPubkey = await createMint(
    connection, // conneciton
    feePayer, // fee payer
    alice.publicKey, // mint authority
    alice.publicKey, // freeze authority (you can use `null` to disable it. when you disable it, you can't turn it on again)
    8, // decimals
  );
  console.log(`mint: ${mintPubkey.toBase58()}`);

  let ata = await createAssociatedTokenAccount(
    connection, // connection
    feePayer, // fee payer
    mintPubkey, // mint
    alice.publicKey, // owner,
  );
  console.log(`ATA: ${ata.toBase58()}`);

  let txhash = await mintToChecked(
    connection, // connection
    feePayer, // fee payer
    mintPubkey, // mint
    ata, // receiver (should be a token account)
    alice, // mint authority
    1e8, // amount. if your decimals is 8, you mint 10^8 for 1 token.
    8, // decimals
  );
  console.log(`txhash: ${txhash}`);

  let txhash2 = await transferChecked(
    connection, // connection
    feePayer, // payer
    ata, // from (should be a token account)
    mintPubkey, // mint
    alice.publicKey, // to (should be a token account)
    alice, // from's owner
    1e8, // amount, if your deciamls is 8, send 10^8 for 1 token
    8, // decimals
  );
  console.log(`txhash: ${txhash}`);
  const mintAccountPublicKey = new PublicKey(
    "8mAKLjGGmjKTnmcXeyr3pr7iX13xXVjJJiL6RujDbSPV",
  );
 
  let mintAccount = await getMint(connection, mintAccountPublicKey);
 
  console.log(mintAccount);
})();