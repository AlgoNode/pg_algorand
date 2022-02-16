package main

import (
	"log"

	"encoding/base32"

	"github.com/algonode/plgo"
	"github.com/algorand/go-algorand-sdk/types"
)

//AddressTxt2Bin converts account address in text form to binary form
func AddressTxt2Bin(data string) []byte {
	logger := plgo.NewErrorLogger("", log.Ltime|log.Lshortfile)
	addr, err := types.DecodeAddress(data)
	if err != nil {
		logger.Fatal(err)
	}
	return addr[:]
}

//AddressBin2Txt converts binary account address to text
func AddressBin2Txt(data []byte) string {
	logger := plgo.NewErrorLogger("", log.Ltime|log.Lshortfile)
	addr, err := types.EncodeAddress(data)
	if err != nil {
		logger.Fatal(err)
	}
	return addr
}

//TxnTxt2Bin converts textual TXN ID to binary
func TxnTxt2Bin(data string) []byte {
	logger := plgo.NewErrorLogger("", log.Ltime|log.Lshortfile)
	decoded, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(data)
	if err != nil {
		logger.Fatal(err)
	}
	return decoded
}

//TxnBin2Txt converts binary TXN ID to text
func TxnBin2Txt(data []byte) string {
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(data)
}
