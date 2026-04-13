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