package main

import (
	"crypto/sha512"
	"log"

	// "encoding/base32"
	"bytes"
	"encoding/binary"
	"errors"
	"reflect"

	"github.com/algorand/go-algorand-sdk/crypto"
	"github.com/algorand/go-algorand-sdk/types"

	"github.com/algonode/plgo"
)

// AddressTxt2Bin converts account address in text form to binary form
func AddressTxt2Bin(data string) []byte {
	addr, err := types.DecodeAddress(data)
	if err != nil {
		logger := plgo.NewErrorLogger("", log.Ltime|log.Lshortfile)
		logger.Fatal(err)
	}
	return addr[:]
}

// AddressBin2Txt converts binary account address to text
func AddressBin2Txt(data []byte) string {
	addr, err := types.EncodeAddress(data)
	if err != nil {
		logger := plgo.NewErrorLogger("", log.Ltime|log.Lshortfile)
		logger.Fatal(err)
	}
	return addr
}

func GetNFDSigNameLSIG(nfdName string, registryAppID int64) []byte {
	lsig, err := getLookupLSIG("name/", nfdName, uint64(registryAppID))
	if err != nil {
		logger := plgo.NewErrorLogger("", log.Ltime|log.Lshortfile)
		logger.Fatal(err)
	}
	addr, err := lsig.Address()
	if err != nil {
		logger := plgo.NewErrorLogger("", log.Ltime|log.Lshortfile)
		logger.Fatal(err)
	}
	return addr[:]
}

func GetNFDSigRevAddressLSIG(pointedToAddress string, registryAppID int64) []byte {
	lsig, err := getLookupLSIG("address/", pointedToAddress, uint64(registryAppID))
	if err != nil {
		logger := plgo.NewErrorLogger("", log.Ltime|log.Lshortfile)
		logger.Fatal(err)
	}
	addr, err := lsig.Address()
	if err != nil {
		logger := plgo.NewErrorLogger("", log.Ltime|log.Lshortfile)
		logger.Fatal(err)
	}
	return addr[:]
}

func GetNFDSigRevAddressBinLSIG(pointedToAddressBin []byte, registryAppID int64) []byte {
	var p2addr types.Address
	copy(p2addr[:], pointedToAddressBin[:sha512.Size256])
	lsig, err := getLookupLSIG("address/", p2addr.String(), uint64(registryAppID))
	if err != nil {
		logger := plgo.NewErrorLogger("", log.Ltime|log.Lshortfile)
		logger.Fatal(err)
	}
	addr, err := lsig.Address()
	if err != nil {
		logger := plgo.NewErrorLogger("", log.Ltime|log.Lshortfile)
		logger.Fatal(err)
	}
	return addr[:]
}

func getLookupLSIG(prefixBytes, lookupBytes string, registryAppID uint64) (crypto.LogicSigAccount, error) {
	sigLookupByteCode := []byte{
		0x05, 0x20, 0x01, 0x01, 0x80, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
		0x07, 0x08, 0x17, 0x35, 0x00, 0x31, 0x18, 0x34, 0x00, 0x12, 0x31, 0x10,
		0x81, 0x06, 0x12, 0x10, 0x31, 0x19, 0x22, 0x12, 0x31, 0x19, 0x81, 0x00,
		0x12, 0x11, 0x10, 0x40, 0x00, 0x01, 0x00, 0x22, 0x43, 0x26, 0x01,
	}
	contractSlice := sigLookupByteCode[6:14]
	if !reflect.DeepEqual(contractSlice, []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}) {
		return crypto.LogicSigAccount{}, errors.New("Lookup template doesn't match expectation")
	}
	binary.BigEndian.PutUint64(contractSlice, registryAppID)

	bytesToAppend := bytes.Join([][]byte{[]byte(prefixBytes), []byte(lookupBytes)}, nil)
	uvarIntBytes := make([]byte, binary.MaxVarintLen64)
	nBytes := binary.PutUvarint(uvarIntBytes, uint64(len(bytesToAppend)))
	composedBytecode := bytes.Join([][]byte{sigLookupByteCode, uvarIntBytes[:nBytes], bytesToAppend}, nil)

	logicSig := crypto.MakeLogicSigAccountEscrow(composedBytecode, [][]byte{})
	return logicSig, nil
}

/*
//TxnTxt2Bin converts textual TXN ID to binary
func TxnTxt2Bin(data string) []byte {
	decoded, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(data)
	if err != nil {
		logger := plgo.NewErrorLogger("", log.Ltime|log.Lshortfile)
		logger.Fatal(err)
	}
	return decoded
}

//TxnBin2Txt converts binary TXN ID to text
func TxnBin2Txt(data []byte) string {
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(data)
}
*/

// func main() {
// 	var (
// 		lsig     crypto.LogicSigAccount
// 		lsigAddr types.Address
// 		err      error
// 	)
// 	name := flag.String("name", "", ".Algo Name for forward lookup - invalid names can be passed here but would never be allowed to be minted...")
// 	address := flag.String("addr", "", "Algorand address for reverse-address lookup")
// 	regAppID := flag.Uint64("id", 760937186, "Registry application id (mainnet defaulted)")
// 	flag.Parse()

// 	if *name == "" && *address == "" {
// 		flag.Usage()
// 		log.Fatalln("You must specify a name, or an address")
// 	}
// 	if *name != "" {
// 		lsig, err = GetNFDSigNameLSIG(*name, *regAppID)
// 	}
// 	if *address != "" {
// 		addr, err := types.DecodeAddress(*address)
// 		if err != nil {
// 			log.Fatalln("Error decoding algoand address parameter:", err)
// 		}
// 		lsig, err = GetNFDSigRevAddressLSIG(addr, *regAppID)
// 	}
// 	if err != nil {
// 		log.Fatalln("error in lsig calculation:", err)
// 	}
// 	lsigAddr, err = lsig.Address()
// 	if err != nil {
// 		log.Fatalln(err)
// 	}
// 	fmt.Println("Registration account:", lsigAddr.String())
// }
