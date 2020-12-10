package formcrypt

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"math/big"
	"net/http"
	"net/http/httptest"
	"reflect"
	"regexp"
	"testing"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
)

const SessionName = "test_session"

func TestGenerate(t *testing.T) {
	// test key generation function
	key1024 := Key{BitSize: 1024}
	err := key1024.Generate()
	if err != nil {
		t.Error("failed to generate 1024-bit key" + err.Error())
	}

	key2048 := Key{BitSize: 2048}
	err = key2048.Generate()
	if err != nil {
		t.Error("failed to generate 2048-bit key" + err.Error())
	}

	key4096 := Key{BitSize: 4096}
	err = key4096.Generate()
	if err != nil {
		t.Error("failed to generate 4096-bit key" + err.Error())
	}

	// testing double generation
	if key1024.Generate() == nil {
		t.Error("double generation of a key variable is allowed")
	}

	// test whether output pk string is in the format [hex string]:[hex string]
	matched, err := regexp.MatchString("^[0-9a-fA-F]+:[0-9a-fA-F]+$", key2048.GetPKHexString())
	if err != nil || !matched {
		t.Error("output of key.GetPKHexString() is not in the correct format")
	}
}

// test whether it decode hex strings and decrypts properly
func TestDecrypt(t *testing.T) {
	key := Key{BitSize: 2048}
	_ = key.Generate()

	// generate a random []byte
	letterBytes := "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	length := big.NewInt(int64(len(letterBytes)))
	b := make([]byte, 32)
	for i := range b {
		idx, _ := rand.Int(rand.Reader, length)
		b[i] = letterBytes[idx.Int64()]
	}

	// encrypt it with the RSA key generated
	enc, err := rsa.EncryptPKCS1v15(rand.Reader, &key.Key.PublicKey, b)
	if err != nil {
		t.Error("failed to encrypt random string: " + err.Error())
	}

	plaintext, err := key.Decrypt(hex.EncodeToString(enc))
	if err != nil || string(b) != plaintext {
		t.Error("failed to decrypt, or decrypted data does not match with original data")
	}
}

// test whether engine and session storage/retrieval is correct (for single session)
func TestEngine(t *testing.T) {
	r := gin.Default()

	// initialize session middleware
	store := cookie.NewStore([]byte("SomeRandomKeyForEncryption"))
	r.Use(sessions.Sessions(SessionName, store))

	err := InitializeEngine(r, SessionName)
	if err != nil {
		t.Error("failed to initialize engine" + err.Error())
	}

	r.GET("/test", func(c *gin.Context) {
		key := Key{BitSize: 2048}
		_ = key.Generate()
		err = key.Store(c, false)
		if err != nil {
			t.Error("failed to store key" + err.Error())
		}

		newKey, err := Load(c, false)
		if err != nil || !reflect.DeepEqual(key, newKey) {
			t.Error("failed to load key")
		}

		// testing key voiding function
		err = Void(c, false)
		if err != nil {
			t.Error("failed to void key" + err.Error())
		}

		newKey, err = Load(c, false)
		if err == nil || !reflect.DeepEqual(Key{}, newKey) {
			t.Error("key is still readable after void() being called")
		}
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/test", nil)
	r.ServeHTTP(w, req)
}

// test whether engine and session storage/retrieval is correct (for many sessions)
func TestEngineMany(t *testing.T) {
	r := gin.Default()

	// initialize session middleware
	store := cookie.NewStore([]byte("SomeRandomKeyForEncryption"))
	r.Use(sessions.SessionsMany([]string{SessionName, "TheOtherSession"}, store))

	err := InitializeEngine(r, SessionName)
	if err != nil {
		t.Error("failed to initialize engine" + err.Error())
	}

	r.GET("/test", func(c *gin.Context) {
		key := Key{BitSize: 2048}
		_ = key.Generate()
		err = key.Store(c, true)
		if err != nil {
			t.Error("failed to store key" + err.Error())
		}

		newKey, err := Load(c, true)
		if err != nil || !reflect.DeepEqual(key, newKey) {
			t.Error("failed to load key")
		}

		// testing key voiding function
		err = Void(c, true)
		if err != nil {
			t.Error("failed to void key" + err.Error())
		}

		newKey, err = Load(c, true)
		if err == nil || !reflect.DeepEqual(Key{}, newKey) {
			t.Error("key is still readable after void() being called")
		}
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/test", nil)
	r.ServeHTTP(w, req)
}
