package main

import (
	"database/sql"
	"encoding/gob"
	"fmt"
	"log"
	picpic "name/codes"
	"net/http"
	"time"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	_ "github.com/go-sql-driver/mysql"
	"golang.org/x/crypto/bcrypt"
)

type User struct {
	ID        string
	Username  string
	Email     string
	pswdHash  string
	CreatedAt string
	Active    string
	verHash   string
	timeout   string
}

var db *sql.DB

func init() {
	gob.Register(&User{})
}

func main() {
	r := gin.Default()
	r.LoadHTMLGlob("static/*.html")

	store := cookie.NewStore([]byte("secret-key"))
	sessionMiddleware := sessions.Sessions("mysession", store)
	r.Use(sessionMiddleware)

	var sqlErr error
	db, sqlErr = sql.Open("mysql", "비밀")
	if sqlErr != nil {
		panic(sqlErr.Error())
	}

	defer db.Close()

	authRouter := r.Group("/user", auth)

	getAllThat(r)

	authRouter.GET("/profile", profileHandler)

	err := r.Run("localhost:8080") // listen and serve on 0.0.0.0:8080 (for windows "localhost:8080")
	if err != nil {
		log.Fatal(err)
	}
}

func auth(c *gin.Context) {
	fmt.Println("auth middleware")
	sess := sessions.Default(c).Get("session")
	fmt.Println("session:", sess)

	if sess == nil {
		c.HTML(http.StatusForbidden, "login.html", nil)
		c.Abort()
		return
	}
	fmt.Println("middleware done")
	c.Next()
}
func getAllThat(r *gin.Engine) {

	r.GET("/hello", picpic.GetHello)
	r.GET("/", getIndex)
	r.Static("/static", "./static")
	r.GET("/greet/:name", picpic.GetGreeting)
	r.GET("/many", picpic.GetMany)
	r.GET("/signup", picpic.GetAccount)
	r.POST("/signup", postAccount)
	r.GET("/login", picpic.LoginGetHandler)
	r.POST("/login", loginPostHandler)
	r.GET("/logout", logoutPostHandler)
}

func profileHandler(c *gin.Context) {
	sess := sessions.Default(c).Get("session")
	var user = &User{}
	var ok bool
	if user, ok = sess.(*User); !ok {
		c.HTML(http.StatusForbidden, "login.html", nil)
	}
	c.HTML(http.StatusOK, "profile.html", gin.H{"user": user})
}

func loginPostHandler(c *gin.Context) {
	var user User
	user.Username = c.PostForm("username")
	password := c.PostForm("userpasswordname")
	err := user.getUserByUsername()
	if err != nil {
		c.HTML(http.StatusUnauthorized, "login.html", nil)
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.pswdHash), []byte(password))
	if err == nil {
		sess := sessions.Default(c)
		sess.Set("session", user)
		sess.Save()

		fmt.Println("session saved")

		c.HTML(http.StatusOK, "index.html", gin.H{
			"message":    "Welcome! " + user.Username,
			"isLoggedIn": true,
		})
		return
	}
	c.HTML(http.StatusUnauthorized, "login.html", nil)

}

func logoutPostHandler(c *gin.Context) {
	sess := sessions.Default(c)
	if sess.Get("session") == nil {
		c.Redirect(http.StatusFound, "/")
		return
	}
	sess.Delete("session")
	sess.Save()

	c.Redirect(http.StatusFound, "/")
}

func (u *User) getUserByUsername() error {
	stmt := "SELECT * FROM users WHERE username = ?"
	row := db.QueryRow(stmt, u.Username)
	err := row.Scan(&u.ID, &u.Username, &u.Email, &u.pswdHash, &u.CreatedAt, &u.Active, &u.verHash, &u.timeout)
	if err != nil {
		fmt.Println("getUserByUsername() err : ", err)
		return err
	}
	return nil
}

func postAccount(c *gin.Context) {
	accId := c.PostForm("name")
	passwordThings := c.PostForm("ppl")
	accEmail := c.PostForm("email")

	pswdHash, _ := bcrypt.GenerateFromPassword([]byte(passwordThings), bcrypt.DefaultCost)
	currTime := time.Now().Format("2006-01-02 15:04:05")

	insertingQuery := "INSERT INTO users(Username, Email, pswdHash, CreatedAt, Active, verHash, timeout) VALUES (?, ?, ?, ?, ?, ?, ?)"
	stmt, err := db.Prepare(insertingQuery)
	if err != nil {
		panic(err)
	}

	_, err = stmt.Exec(accId, accEmail, string(pswdHash), currTime, 1, string(pswdHash), currTime)

	if err != nil {
		c.HTML(http.StatusUnauthorized, "signup.html", gin.H{"message": "Please retry"})
		return
	}

	c.HTML(http.StatusOK, "thingsResult.html", gin.H{"name": accId})
}

func siteLoggedIn(c *gin.Context) bool {
	errCheck := sessions.Default(c).Get("session")
	if errCheck == nil {
		return false
	}
	return true
}

func getIndex(c *gin.Context) {
	if siteLoggedIn(c) {
		c.HTML(http.StatusOK, "index.html", gin.H{
			"isLoggedIn": true,
		})
		return
	}
	c.HTML(http.StatusOK, "index.html", gin.H{
		"isLoggedIn": false,
	})
}
