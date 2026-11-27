package apk

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"strings"
	"testing"

	starfile "github.com/tinyrange/trex/storage/star"
)

func apkMember(t *testing.T, name string, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zip := gzip.NewWriter(&buf)
	writer := tar.NewWriter(zip)
	if err := writer.WriteHeader(&tar.Header{Name: name, Mode: 0644, Size: int64(len(data))}); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := zip.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestReadSignedIndex(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	const entry = "C:Q1AAAAAAAAAAAAAAAAAAAAAAAAAAA=\nP:jq\nV:1.8.1-r0\nA:x86_64\nS:120\nI:130\nT:JSON processor\nD:so:libonig.so.5\n"
	longField := "p:" + strings.Repeat("cmd:extra ", 9000) + "\n"
	index := apkMember(t, "APKINDEX", []byte(entry+longField))
	hash := sha256.Sum256(index)
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, hash[:])
	if err != nil {
		t.Fatal(err)
	}
	signatures := apkMember(t, ".SIGN.RSA256.test.rsa.pub", signature)
	keys := map[string]*rsa.PublicKey{"test.rsa.pub": &key.PublicKey}
	file := &starfile.Bytes{Data: append(bytes.Clone(signatures), index...)}
	records, err := ReadIndex(file, keys)
	if err != nil || len(records) != 1 || records[0].Name != "jq" || len(records[0].Provides) != 9000 {
		t.Fatalf("signed index: %d records, %v", len(records), err)
	}
	changed := apkMember(t, "APKINDEX", []byte(strings.Replace(entry, "P:jq", "P:other", 1)))
	file = &starfile.Bytes{Data: append(bytes.Clone(signatures), changed...)}
	if _, err := ReadIndex(file, keys); err == nil {
		t.Fatal("accepted an index whose signature did not match its contents")
	}
}
