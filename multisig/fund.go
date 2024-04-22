// fund.go - Funding P2SH address from a Bitcoin address.
package multisig

import (
	"github.com/g0dd0ghd/go-bitcoin-multisig/btcutils"
	"github.com/prettymuchbryce/hellobitcoin/base58check"
	secp256k1 "github.com/btccom/secp256k1-go/secp256k1"

	"bytes"
	"encoding/hex"
	"fmt"
	"log"
)

// OutputFund formats and prints relevant outputs to the user.
func OutputFund(flagPrivateKey string, flagInputTx string, flagAmount int, flagP2SHDestination string) {
	finalTransactionHex := generateFund(flagPrivateKey, flagInputTx, flagAmount, flagP2SHDestination)

	//Output our final transaction
	fmt.Printf(`
-----------------------------------------------------------------------------------------------------------------------------------
Your raw funding transaction is:
%v
Broadcast this transaction to fund your P2SH address.
-----------------------------------------------------------------------------------------------------------------------------------
`,
		finalTransactionHex,
	)
}

// generateFund is the high-level logic for funding any P2SH address with the 'go-bitcoin-multisig fund' subcommand.
// Takes flagPrivateKey (private key of input Bitcoins to fund with), flagInputTx (input transaction hash of
// Bitcoins to fund with), flagAmount (amount in Satoshis to send, with balance left over from input being used
// as transaction fee) and flagP2SHDestination (destination P2SH multisig address which is being funded) as arguments.
func generateFund(flagPrivateKey string, flagInputTx string, flagAmount int, flagP2SHDestination string) string {
	//Get private key as decoded raw bytes
	privateKey := base58check.Decode(flagPrivateKey)
	//In order to construct the raw transaction we need the input transaction hash,
	//the P2SH destination address, the number of satoshis to send, and the scriptSig
	//which is temporarily (prior to signing) the ScriptPubKey of the input transaction.
	publicKey, err := btcutils.NewPublicKey(privateKey)
	if err != nil {
		log.Fatal(err)
	}

	ctx, err := secp256k1.ContextCreate(secp256k1.ContextSign | secp256k1.ContextVerify)
	if err != nil {
		log.Fatal(err)
	}

	_, pubKeyByte, err := secp256k1.EcPubkeySerialize(ctx, publicKey, secp256k1.EcCompressed)
	if err != nil {
		log.Fatal(err)
	}
	publicKeyHash, err := btcutils.Hash160(pubKeyByte)
	if err != nil {
		log.Fatal(err)
	}
	tempScriptSig, err := btcutils.NewP2PKHScriptPubKey(publicKeyHash)
	if err != nil {
		log.Fatal(err)
	}
	redeemScriptHash := base58check.Decode(flagP2SHDestination)
	//Create our scriptPubKey
	scriptPubKey, err := btcutils.NewP2SHScriptPubKey(redeemScriptHash)
	if err != nil {
		log.Fatal(err)
	}
	//Create unsigned raw transaction
	rawTransaction, err := btcutils.NewRawTransaction(flagInputTx, flagAmount, tempScriptSig, scriptPubKey)
	if err != nil {
		log.Fatal(err)
	}
	//After completing the raw transaction, we append
	//SIGHASH_ALL in little-endian format to the end of the raw transaction.
	hashCodeType, err := hex.DecodeString("01000000")
	if err != nil {
		log.Fatal(err)
	}
	var rawTransactionBuffer bytes.Buffer
	rawTransactionBuffer.Write(rawTransaction)
	rawTransactionBuffer.Write(hashCodeType)
	rawTransactionWithHashCodeType := rawTransactionBuffer.Bytes()
	//Sign the raw transaction, and output it to the console.
	finalTransaction, err := signP2PKHTransaction(rawTransactionWithHashCodeType, privateKey, scriptPubKey, flagInputTx, flagAmount)
	if err != nil {
		log.Fatal(err)
	}
	finalTransactionHex := hex.EncodeToString(finalTransaction)

	return finalTransactionHex
}

// signP2PKHTransaction signs a raw P2PKH transaction, given a private key and the scriptPubKey, inputTx and amount
// to construct the final transaction.
func signP2PKHTransaction(rawTransaction []byte, privateKey []byte, scriptPubKey []byte, inputTx string, amount int) ([]byte, error) {
	publicKey, err := btcutils.NewPublicKey(privateKey)
	if err != nil {
		return nil, err
	}
	signature, err := btcutils.NewSignature(rawTransaction, privateKey)
	if err != nil {
		return nil, err
	}
	hashCodeType, err := hex.DecodeString("01")
	if err != nil {
		return nil, err
	}

	ctx, err := secp256k1.ContextCreate(secp256k1.ContextSign | secp256k1.ContextVerify)
	if err != nil {
		log.Fatal(err)
	}

	//Convert secp256k1 signature to compact format (64 byte)
	_, signatureCompact, err := secp256k1.EcdsaSignatureSerializeCompact(ctx, signature)
	if err != nil {
		log.Fatal(err)
	}

	_, pubKeyByte, err := secp256k1.EcPubkeySerialize(ctx, publicKey, secp256k1.EcCompressed)
	if err != nil {
		log.Fatal(err)
	}

	//signatureLength is +1 to add hashCodeType
	signatureLength := byte(len(signatureCompact) + 1)
	//Create scriptSig
	var buffer bytes.Buffer
	buffer.WriteByte(signatureLength)
	buffer.Write(signatureCompact)
	buffer.WriteByte(hashCodeType[0])
	buffer.WriteByte(byte(len(pubKeyByte)))
	buffer.Write(pubKeyByte)
	scriptSig := buffer.Bytes()
	//Finally create transaction with actual scriptSig
	signedRawTransaction, err := btcutils.NewRawTransaction(inputTx, amount, scriptSig, scriptPubKey)
	if err != nil {
		return nil, err
	}
	return signedRawTransaction, nil
}
