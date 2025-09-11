package main

/*
#cgo CFLAGS: -I"/usr/include/postgresql/16/server" -fpic
#cgo LDFLAGS: -shared

#include "postgres.h"
#include "fmgr.h"
#include "pgtime.h"
#include "access/htup_details.h"
#include "catalog/pg_type.h"
#include "utils/builtins.h"
#include "utils/date.h"
#include "utils/timestamp.h"
#include "utils/array.h"
#include "utils/elog.h"
#include "executor/spi.h"
#include "parser/parse_type.h"
#include "commands/trigger.h"
#include "utils/builtins.h"
#include "utils/rel.h"
#include "utils/lsyscache.h"
#include "utils/jsonb.h"
#include "funcapi.h"

// Declarations of auxiliary functions
//
// These functions are defined in the .c file.
//
// We need these auxiliary wrappers to overcome the CGO limitation of not being able to reference macros.
// These macros are wrapped within functions in order to be able to access the functionality.

void elog_notice(char* string);
void elog_error(char* string);
*/
import "C"
import (
	"bytes"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"reflect"
	"unsafe"

	"github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/types"
)

func main() {}

//export AddressTxt2Bin
func AddressTxt2Bin(
	p *C.char,
	out *byte, // len is 32 by convention
) {
	// turn the input C string into a Go string
	var data string = C.GoString(p)

	// attempt to decode an address from it
	addr, err := types.DecodeAddress(data)
	if err != nil {
		cp := C.CString(err.Error())
		defer C.free(unsafe.Pointer(cp))
		C.elog_error(cp)
		return
	}

	// write to C memory
	array := unsafe.Slice(out, 32)
	copy(array, addr[:])
}

//export AddressBin2Txt
func AddressBin2Txt(
	in *byte,
	out *byte,
) {
	// cast the input pointer into []byte
	data := unsafe.Slice(in, 32)

	// attempt to encode an address out of it
	addr, err := types.EncodeAddress(data)
	if err != nil {
		cp := C.CString(err.Error())
		defer C.free(unsafe.Pointer(cp))
		C.elog_error(cp)
		return
	}

	// write to C memory
	array := unsafe.Slice(out, 58)
	copy(array, []byte(addr))
}

//export GetNFDSigNameLSIG
func GetNFDSigNameLSIG(
	pNfdName *C.char,
	registryAppID int64,
	out *byte,
) {

	// turn the input C string into a Go string
	var nfdName string = C.GoString(pNfdName)

	// look up the address associated with the NFD name
	lsig, err := getLookupLSIG("name/", nfdName, uint64(registryAppID))
	if err != nil {
		cp := C.CString(err.Error())
		defer C.free(unsafe.Pointer(cp))
		C.elog_error(cp)
	}
	addr, err := lsig.Address()
	if err != nil {
		cp := C.CString(err.Error())
		defer C.free(unsafe.Pointer(cp))
		C.elog_error(cp)
	}

	// write to C memory
	array := unsafe.Slice(out, 58)
	copy(array, addr[:])
}

//export GetNFDSigRevAddressLSIG
func GetNFDSigRevAddressLSIG(
	pPointedToAddress *C.char,
	registryAppID int64,
	out *byte,
) {
	// turn the input C string into a Go string
	var pointedToAddress string = C.GoString(pPointedToAddress)

	lsig, err := getLookupLSIG("address/", pointedToAddress, uint64(registryAppID))
	if err != nil {
		cp := C.CString(err.Error())
		defer C.free(unsafe.Pointer(cp))
		C.elog_error(cp)
	}
	addr, err := lsig.Address()
	if err != nil {
		cp := C.CString(err.Error())
		defer C.free(unsafe.Pointer(cp))
		C.elog_error(cp)
	}

	// write to C memory
	array := unsafe.Slice(out, 58)
	copy(array, addr[:])
}

//export GetNFDSigRevAddressBinLSIG
func GetNFDSigRevAddressBinLSIG(
	pPointedToAddressBin *byte,
	registryAppID int64,
	out *byte,
) {
	// cast the input pointer into []byte
	pointedToAddressBin := unsafe.Slice(pPointedToAddressBin, 32)

	var p2addr types.Address
	copy(p2addr[:], pointedToAddressBin[:sha512.Size256])
	lsig, err := getLookupLSIG("address/", p2addr.String(), uint64(registryAppID))
	if err != nil {
		cp := C.CString(err.Error())
		defer C.free(unsafe.Pointer(cp))
		C.elog_error(cp)
	}
	addr, err := lsig.Address()
	if err != nil {
		cp := C.CString(err.Error())
		defer C.free(unsafe.Pointer(cp))
		C.elog_error(cp)
	}

	// write to C memory
	array := unsafe.Slice(out, 58)
	copy(array, addr[:])
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

	logicSig, err := crypto.MakeLogicSigAccountEscrowChecked(composedBytecode, [][]byte{})
	if err != nil {
		return crypto.LogicSigAccount{}, err
	}

	return logicSig, nil
}
