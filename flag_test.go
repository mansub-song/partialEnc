package encrypt

import (
	// "github.com/ethereum/go-ethereum/common/hexutil"
	"fmt"
	"testing"
)

func TestVerifySignature(t *testing.T) {
	key, msg, sig := Init()
	if !VerifySignature(key, msg, sig) {
		t.Error("VerifySignature returned true for malleable signature")
	}
}

func TestChunkOption(t *testing.T) {
	opt := "myverystrongpasswordo32bitlength-049a7df67f79246283fdc93af76d4f8cdd62c4886e8cd870944e817dd0b97934fdd7719d0810951e03418205868a5c1b40b192451367f28e0088dd75e15de40c05-1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8-789a80053e4927d0a898db8e065e948f5cf086e32f9ccaa54c1908e22ac430c62621578113ddbb62d509bf6049b8fb544ab06d36f916685a2eb8e57ffadde02301"
	enCryptionKey, publicKey, hash, signature := ChunkOption(opt)
	fmt.Printf("TestChunkOption: %x %x %x %x\n", enCryptionKey, publicKey, hash, signature)

	// key, msg, sig := Init()
	// if !VerifySignature(key, msg, sig) {
	// 	t.Error("VerifySignature returned true for malleable signature")
	// }
}

func TestExtractEncryptionKey(t *testing.T) {
	opt := "myverystrongpasswordo32bitlength-049a7df67f79246283fdc93af76d4f8cdd62c4886e8cd870944e817dd0b97934fdd7719d0810951e03418205868a5c1b40b192451367f28e0088dd75e15de40c05-1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8-789a80053e4927d0a898db8e065e948f5cf086e32f9ccaa54c1908e22ac430c62621578113ddbb62d509bf6049b8fb544ab06d36f916685a2eb8e57ffadde02301"
	key := ExtractEncryptionKey(opt)
	fmt.Printf("%x\n", key)
}
