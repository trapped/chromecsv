package main

/*
#cgo LDFLAGS: -lCrypt32
#define NOMINMAX
#include <windows.h>
#include <Wincrypt.h>

char* decrypt(byte* in, int len, int *outLen) {
	DATA_BLOB input, output;
	LPWSTR pDescrOut =  NULL;
	input.cbData = len;
	input.pbData = in;
	CryptUnprotectData(
		&input,
		&pDescrOut,
		NULL,                 // Optional entropy
		NULL,                 // Reserved
		NULL,                 // Here, the optional
							  // prompt structure is not
							  // used.
		0,
		&output);
	*outLen = output.cbData;
	return output.pbData;
}

void doFree(char* ptr) {
	free(ptr);
}
*/
import "C"
import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"io/ioutil"
	"path/filepath"
)

const Chrome80AESFormatVersion = 19

type WindowsCrypt struct {
	loginsVer int
	masterKey []byte
}

func NewCrypt(loginsVer int, path string) crypt {
	if loginsVer >= Chrome80AESFormatVersion {
		localStatePath := filepath.Join(path, "Local State")
		masterKey := readMasterKey(localStatePath)
		return &WindowsCrypt{loginsVer, masterKey}
	} else {
		return &WindowsCrypt{loginsVer: loginsVer}
	}
}

func (wc *WindowsCrypt) decrypt(input []byte) string {
	if wc.loginsVer >= Chrome80AESFormatVersion {
		// since Chrome v80, password are encrypted using AES with a logon-derived master key
		nonce, payload := input[3:15], input[15:]
		block, err := aes.NewCipher(wc.masterKey)
		if err != nil {
			panic(err)
		}
		aesgcm, err := cipher.NewGCM(block)
		if err != nil {
			panic(err)
		}
		decrypted, err := aesgcm.Open(nil, nonce, payload, nil)
		if err != nil {
			panic(err)
		}
		// remove suffix
		return string(decrypted[:len(decrypted)-16])
	} else {
		// previously they were encrypted simply using the win32 crypto API
		return string(win32CryptUnprotectData(input))
	}
}

func win32CryptUnprotectData(input []byte) []byte {
	var length C.int
	decryptedC := C.decrypt((*C.byte)(&input[0]), C.int(len(input)), &length)
	decrypted := C.GoBytes(decryptedC, length)
	return decrypted
}

func readMasterKey(localStatePath string) []byte {
	localStateData, err := ioutil.ReadFile(localStatePath)
	if err != nil {
		panic(err)
	}
	localState := make(map[string]interface{})
	if err := json.Unmarshal(localStateData, &localState); err != nil {
		panic(err)
	}
	encryptedKey, err := base64.StdEncoding.DecodeString(
		localState["os_crypt"].(map[string]interface{})["encrypted_key"].(string))
	if err != nil {
		panic(err)
	}
	// strip DPAPI magic string and decrypt
	return win32CryptUnprotectData(encryptedKey[5:])
}
