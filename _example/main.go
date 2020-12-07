package main

import (
	"html/template"
	"log"
	"net/http"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"

	"github.com/fsgmhoward/formcrypt.go"
)

func main() {
	r := gin.Default()
	store := cookie.NewStore([]byte("some_random_char"))
	sessionName := "mySession"
	r.Use(sessions.Sessions(sessionName, store))
	r.LoadHTMLGlob("templates/*")

	err := formcrypt.InitializeEngine(r, sessionName)
	if err != nil {
		log.Fatal("Unable to initialize StatikFS")
	}
	r.GET("/", func(c *gin.Context) {
		key := formcrypt.Key{BitSize: 2048}
		err := key.Generate()
		if err != nil {
			c.String(http.StatusInternalServerError, "error in generating the key: "+err.Error())
			return
		}
		err = key.Store(c, false)
		if err != nil {
			c.String(http.StatusInternalServerError, "error in storing key: "+err.Error())
			return
		}
		js := key.GetJavascriptSegment("form_id", []string{"password"})
		c.HTML(http.StatusOK, "index.tmpl", gin.H{
			"js": template.HTML(js),
		})
	})

	r.POST("/", func(c *gin.Context) {
		key, err := formcrypt.Load(c, false)
		if err != nil {
			c.String(http.StatusInternalServerError, "error in loading key: "+err.Error())
			return
		}
		plaintext, err := key.Decrypt(c.PostForm("password"))
		if err != nil {
			c.String(http.StatusInternalServerError, "error in decrypting data: "+err.Error())
			return
		}
		err = formcrypt.Void(c, false)
		if err != nil {
			c.String(http.StatusInternalServerError, "error in deleting key: "+err.Error())
			return
		}
		c.String(http.StatusOK, "Data received:\nfname="+c.PostForm("fname")+"\npassword="+plaintext)
	})

	r.Run(":8000")
}
