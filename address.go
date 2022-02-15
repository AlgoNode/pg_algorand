package main

import (
	"log"

	"github.com/algorand/go-algorand-sdk/types"
	"gitlab.com/microo8/plgo"
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
