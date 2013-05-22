package fernet

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"time"
)

const ivCap = (aes.BlockSize + 2) / 3 * 3

var pipe = []byte{'|'}

func jsonVerify(tok []byte, ttl time.Duration, now time.Time, k Key) []byte {
	signingKey, cryptKey := k.signBytes(), k.cryptBytes()
	i := bytes.LastIndex(tok, pipe)
	if i == -1 {
		return nil
	}
	fields, machex := tok[:i], tok[i+1:]
	hmac := make([]byte, sha256.Size)
	n, err := hex.Decode(hmac, machex)
	if err != nil || n != len(hmac) {
		return nil
	}

	// key and message are intentionally reversed to match behavior
	// of ruby-fernet.
	newHash := genhmac(signingKey, fields)
	if subtle.ConstantTimeCompare(hmac, newHash) != 1 {
		return nil
	}
	s := bytes.Split(fields, pipe)
	if len(s) != 2 {
		return nil
	}
	pb64, ivb64 := s[0], s[1]
	pCap := encoding.DecodedLen(len(pb64))
	p := b64dec(make([]byte, pCap), pb64)
	if p == nil {
		return nil
	}
	iv := b64dec(make([]byte, ivCap), ivb64)
	if iv == nil {
		return nil
	}

	if len(p)%aes.BlockSize != 0 || len(iv) != aes.BlockSize {
		return nil
	}
	bc, err := aes.NewCipher(cryptKey)
	if err != nil {
		return nil
	}

	cipher.NewCBCDecrypter(bc, iv).CryptBlocks(p, p)
	msg := unpad(p)
	if msg == nil {
		return nil
	}
	var parsedMsg struct {
		Time string `json:"issued_at"`
	}
	err = json.Unmarshal(msg, &parsedMsg)
	if err != nil {
		return nil
	}
	issuedAt, err := time.Parse(time.RFC3339, parsedMsg.Time)
	if err != nil {
		// try again
		issuedAt, err = time.Parse("2006/01/02 15:04:05 -0700", parsedMsg.Time)
		if err != nil {
			return nil
		}
	}
	if now.After(issuedAt.Add(ttl)) {
		return nil
	}
	return msg
}
