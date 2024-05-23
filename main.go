package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"fmt"

	"github.com/aead/cmac"
)

func DecryptAES(key []byte, data []byte) []byte {
	c, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	cbc := cipher.NewCBCDecrypter(c, make([]byte, 16))
	dst := make([]byte, len(data))
	cbc.CryptBlocks(dst, data)

	return dst
}

func AESMAC(key []byte, data []byte) []byte {
	cipher, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	h, err := cmac.NewWithTagSize(cipher, 16)
	if err != nil {
		panic(err)
	}

	_, err = h.Write(data)
	if err != nil {
		panic(err)
	}

	result := h.Sum(nil)

	return result
}

func ShortAESMAC(key []byte, data []byte) []byte {
	result := AESMAC(key, data)
	finalResult := []byte{result[1], result[3], result[5], result[7], result[9], result[11], result[13], result[15]}

	return finalResult
}

func ShortAESMAC_Result(result []byte) []byte {
	finalResult := []byte{result[1], result[3], result[5], result[7], result[9], result[11], result[13], result[15]}

	return finalResult
}

func displayDecryptedData(decPICCData []byte) {
	piccDataTag := hex.EncodeToString(decPICCData[0:1])
	uid := hex.EncodeToString(decPICCData[1:8])
	sdmReadCtr := hex.EncodeToString(decPICCData[8:11])
	fmt.Printf("\nDecrypted PICCData: %s\n", hex.EncodeToString(decPICCData))
	fmt.Printf("PICCDataTag: %s\n", piccDataTag)
	fmt.Printf("UID: %s\n", uid)
	fmt.Printf("SDMReadCtr: %s\n", sdmReadCtr)
}

func printCMACs(calculatedCMAC, expectedCMAC []byte) {
	fmt.Printf("Calculated CMAC: %s\n", hex.EncodeToString(calculatedCMAC))
	fmt.Printf("Expected CMAC: %s\n", hex.EncodeToString(expectedCMAC))
}

var zeroKey = "00000000000000000000000000000000"
var e = "DB3D685E910F568159533A466914E9B3"
var c = "7214E8B275EF0B19"

func main() {
	key, _ := hex.DecodeString(zeroKey)
	data, _ := hex.DecodeString(e)
	results := DecryptAES(key, data)

	displayDecryptedData(results)

	// testKey1, _ := hex.DecodeString(zeroKey)
	// ex1, _ := hex.DecodeString(e)
	expectedC, _ := hex.DecodeString(c)

	// result := ShortAESMAC(testKey1, ex1)

	// GenerateAESSessionMACKey()

	metaBytes, _ := hex.DecodeString(e)
	meta := Deserialize(metaBytes)
	fmt.Println("meta Uid : ", meta.Uid)
	fmt.Println("meta ReadCounter : ", meta.ReadCounter)
	newKey := meta.GenerateAESSessionMACKey(key)

	fmt.Println("newKey : ", newKey)

	newKeyCut := ShortAESMAC_Result(newKey)

	fmt.Println("newKeyCut : ", newKeyCut)

	printCMACs(newKeyCut, expectedC)
}
