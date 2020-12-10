package formcrypt

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/gob"
	"encoding/hex"
	"errors"
	"math/big"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/rakyll/statik/fs"

	_ "github.com/fsgmhoward/formcrypt.go/statik"
)

const DefaultKey = "github.com/fsgmhoward/formcrypt.go"
const DefaultSessionKey = "formcrypt.go/key"

// stores some global data
type Engine struct {
	SessionName string
}

type Key struct {
	BitSize   int
	Key       rsa.PrivateKey
	generated bool
}

/*
 * key generation and manipulation functions
 */

// generator of the RSA key
func (key *Key) Generate() error {
	if key.generated {
		// we won't generate a key twice - this is potentially an error
		return errors.New("formcrypt.go: attempt to generate a key twice was denied")
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, key.BitSize)
	if err != nil {
		return err
	}
	key.Key = *rsaKey
	key.generated = true
	return nil
}

// generate the base64-encoded public key string
// in the form of N:E
func (key *Key) GetPKHexString() string {
	n := key.Key.PublicKey.N.Bytes()
	e := new(big.Int).SetInt64(int64(key.Key.PublicKey.E)).Bytes()
	return hex.EncodeToString(n) + ":" + hex.EncodeToString(e)
}

// generate a javascript segment for inserting into HTML
func (key *Key) GetJavascriptSegment(formId string, fields []string) string {
	fieldString := "["
	isFirst := true
	for _, field := range fields {
		if isFirst {
			isFirst = false
		} else {
			fieldString += ", "
		}
		fieldString += "\"" + field + "\""
	}
	fieldString += "]"
	return "" +
		"<script src=\"/formcrypt_assets/prng4.js\"></script>\n" +
		"<script src=\"/formcrypt_assets/rng.js\"></script>\n" +
		"<script src=\"/formcrypt_assets/jsbn.js\"></script>\n" +
		"<script src=\"/formcrypt_assets/rsa.js\"></script>\n" +
		"<script>\n" +
		"var formcrypt_pk = \"" + key.GetPKHexString() + "\".split(\":\");\n" +
		"var formcrypt_fields = " + fieldString + ";\n" +
		"var k = new RSAKey();\n" +
		"k.setPublic(formcrypt_pk[0], formcrypt_pk[1]);\n" +
		"document.addEventListener('DOMContentLoaded', () => {\n" +
		"    document.getElementById(\"" + formId + "\").addEventListener(\"submit\", () => {\n" +
		"        formcrypt_fields.forEach(f => {var e = document.getElementById(f); e.value = k.encrypt(e.value);});\n" +
		"    });\n" +
		"}, false);\n" +
		"</script>\n"
}

/*
 * decryption related functions
 */

// decrypts data received from client
func (key *Key) Decrypt(dataString string) (string, error) {
	data, err := hex.DecodeString(dataString)
	if err != nil {
		return "", err
	}

	// opts set to nil to use PKCS#1 decryption
	plaintext, err := key.Key.Decrypt(rand.Reader, data, nil)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}

/*
 * session related functions
 */

// get the current session for formcrypt
func getSession(c *gin.Context, isMany bool) sessions.Session {
	var session sessions.Session
	if isMany {
		session = sessions.DefaultMany(c, c.MustGet(DefaultKey).(Engine).SessionName)
	} else {
		session = sessions.Default(c)
	}
	return session
}

// store the key into the session
// isMany specifies whether multiple session is used
func (key *Key) Store(c *gin.Context, isMany bool) error {
	session := getSession(c, isMany)
	session.Set(DefaultSessionKey, *key)
	return session.Save()
}

// load the key from the session
// if key cannot be loaded, it should return an empty key with error
func Load(c *gin.Context, isMany bool) (Key, error) {
	key := getSession(c, isMany).Get(DefaultSessionKey)
	if key == nil {
		return Key{}, errors.New("no key stored in session")
	}
	return key.(Key), nil
}

// delete the stored key from session
func Void(c *gin.Context, isMany bool) error {
	session := getSession(c, isMany)
	session.Set(DefaultSessionKey, nil)
	return session.Save()
}

/*
 * helper functions
 */

// initialize gin engine - adds routes for static assets and adds session middleware
func InitializeEngine(r *gin.Engine, sessionName string) error {
	gob.Register(Key{})
	statikFS, err := fs.New()
	if err != nil {
		return err
	}
	r.StaticFS("/formcrypt_assets", statikFS)
	r.Use(func(c *gin.Context) {
		c.Set(DefaultKey, Engine{SessionName: sessionName})
		c.Next()
	})
	return nil
}
