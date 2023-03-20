package encrypt

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"strings"

	"github.com/ethereum/go-ethereum/crypto"
)

var encryptionFlag = false
var decryptionFlag = false

func SetEncryptionFlag(flag bool) {
	encryptionFlag = flag
}

func GetEncryptionFlag() bool {
	return encryptionFlag
}

func SetDecryptionFlag(flag bool) {
	decryptionFlag = flag
}

func GetDecryptionFlag() bool {
	return decryptionFlag
}

func StreamToByte(stream io.Reader) []byte {
	buf := new(bytes.Buffer)
	buf.ReadFrom(stream)
	return buf.Bytes()
}

func ChunkOption(opt string) ([]byte, []byte, []byte, []byte) {
	// fmt.Println("opt:", opt)
	tempStrings := strings.Split(opt, "-")
	// fmt.Println("tempStrings:", tempStrings)
	// encryptionKey, _ := hex.DecodeString(tempStrings[0]) // hex를 표현하는 string을 hex값으로 변환
	encryptionKey := []byte(tempStrings[0]) // hex를 표현하는 string을 hex값으로 변환
	publicKey, _ := hex.DecodeString(tempStrings[1])
	hash, _ := hex.DecodeString(tempStrings[2])
	signature, _ := hex.DecodeString(tempStrings[3])
	return encryptionKey, publicKey, hash, signature
}

func ExtractEncryptionKey(opt string) []byte {
	encryptionKey, publicKey, hash, signature := ChunkOption(opt)
	if !VerifySignature(publicKey, hash, signature) {
		panic("error - verifysignature")
	}
	return encryptionKey
}

func VerifySignature(pubkey, hash, signature []byte) bool {
	signatureNoRecoverID := signature[:len(signature)-1] // remove recovery id
	verified := crypto.VerifySignature(pubkey, hash, signatureNoRecoverID)
	fmt.Println("mssong:", verified) // true
	return verified
}

func Init() ([]byte, []byte, []byte) {
	privateKey, err := crypto.HexToECDSA("fad9c8855b740a0b7ed4c221dbad0f33a83a49cad6b3fe8d5817ac83d38b6a19")
	if err != nil {
		log.Fatal(err)
	}
	publicKey := privateKey.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		log.Fatal("error casting public key to ECDSA")
	}

	publicKeyBytes := crypto.FromECDSAPub(publicKeyECDSA)

	data := []byte("hello")
	hash := crypto.Keccak256Hash(data)

	signature, err := crypto.Sign(hash.Bytes(), privateKey)
	if err != nil {
		log.Fatal(err)
	}

	// sigPublicKey, err := crypto.Ecrecover(hash.Bytes(), signature)
	// if err != nil {
	//     log.Fatal(err)
	// }

	// matches := bytes.Equal(sigPublicKey, publicKeyBytes)
	// fmt.Println(matches) // true

	sigPublicKeyECDSA, err := crypto.SigToPub(hash.Bytes(), signature)
	if err != nil {
		log.Fatal(err)
	}

	sigPublicKeyBytes := crypto.FromECDSAPub(sigPublicKeyECDSA)
	// matches = bytes.Equal(sigPublicKeyBytes, publicKeyBytes)
	// fmt.Println(matches) // true

	signatureNoRecoverID := signature[:len(signature)-1] // remove recovery id
	verified := crypto.VerifySignature(publicKeyBytes, hash.Bytes(), signatureNoRecoverID)
	fmt.Println(verified) // true
	// fmt.Println(string(sigPublicKeyBytes), string(hash.Bytes()), string(signature))
	// fmt.Printf("%x %x %x\n", sigPublicKeyBytes, hash.Bytes(), signature)
	// fmt.Println(len(string(sigPublicKeyBytes)), len(string(hash.Bytes())), len(string(signature)))
	// fmt.Println(len(sigPublicKeyBytes), len(hash.Bytes()), len(signature))

	return sigPublicKeyBytes, hash.Bytes(), signature
}
