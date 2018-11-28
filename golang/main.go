package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/gob"
	"encoding/json"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"

	"github.com/codegangsta/negroni"
	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"golang.org/x/oauth2"

	"github.com/joho/godotenv"
)

var store sessions.Store

func main() {

	// err := godotenv.Load()
	// if err != nil {
	// 	log.Fatal("Error loading .env file")
	// }
	godotenv.Load()

	store = sessions.NewCookieStore([]byte(os.Getenv("SESSIONS_SECRET")))
	gob.Register(map[string]interface{}{})

	r := mux.NewRouter()
	r.HandleFunc("/", HomeHandler)
	r.HandleFunc("/login", LoginHandler)
	r.HandleFunc("/logout", LogoutHandler)
	r.HandleFunc("/callback", CallbackHandler)
	r.Handle("/user", negroni.New(
		negroni.HandlerFunc(IsAuthenticated),
		negroni.Wrap(http.HandlerFunc(UserHandler)),
	))

	r.PathPrefix("/public/").Handler(http.StripPrefix("/public/", http.FileServer(http.Dir("public/"))))

	http.Handle("/", r)
	log.Print("Server listening on http://localhost:3000/")
	http.ListenAndServe("0.0.0.0:3000", nil)
}

// HomeHandler handle home page request
func HomeHandler(w http.ResponseWriter, r *http.Request) {
	data := struct {
		Auth0ClientID     string
		Auth0ClientSecret string
		Auth0Domain       string
		Auth0CallbackURL  template.URL
	}{
		os.Getenv("AUTH0_CLIENT_ID"),
		os.Getenv("AUTH0_CLIENT_SECRET"),
		os.Getenv("AUTH0_DOMAIN"),
		template.URL(os.Getenv("AUTH0_CALLBACK_URL")),
	}

	RenderTemplate(w, "home", data)
}

// LoginHandler is a login handler for OAuth login
func LoginHandler(w http.ResponseWriter, r *http.Request) {
	domain := os.Getenv("AUTH0_DOMAIN")
	aud := os.Getenv("AUDIENCE")

	conf := &oauth2.Config{
		ClientID:     os.Getenv("AUTH0_CLIENT_ID"),
		ClientSecret: os.Getenv("AUTH0_CLIENT_SECRET"),
		RedirectURL:  os.Getenv("AUTH0_CALLBACK_URL"),
		Scopes:       []string{"openid", "profile"},
		Endpoint: oauth2.Endpoint{
			AuthURL:  "https://" + domain + "/authorize",
			TokenURL: "https://" + domain + "/oauth/token",
		},
	}

	if aud == "" {
		aud = "https://" + domain + "/userinfo"
	}

	b := make([]byte, 32)
	rand.Read(b)
	state := base64.StdEncoding.EncodeToString(b)

	session, err := store.Get(r, "state")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	session.Values["state"] = state
	err = session.Save(r, w)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	audienceOpts := oauth2.SetAuthURLParam("audience", aud)
	url := conf.AuthCodeURL(state, audienceOpts)

	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

// LogoutHandler logout handle
func LogoutHandler(w http.ResponseWriter, r *http.Request) {

	domain := os.Getenv("AUTH0_DOMAIN")

	var Url *url.URL
	Url, err := url.Parse("https://" + domain)

	if err != nil {
		panic("boom")
	}

	Url.Path += "/v2/logout"
	parameters := url.Values{}
	parameters.Add("returnTo", "http://localhost:3000")
	parameters.Add("client_id", os.Getenv("AUTH0_CLIENT_ID"))
	Url.RawQuery = parameters.Encode()

	http.Redirect(w, r, Url.String(), http.StatusTemporaryRedirect)
}

// CallbackHandler is a callback handler for Authorization flow
func CallbackHandler(w http.ResponseWriter, r *http.Request) {
	domain := os.Getenv("AUTH0_DOMAIN")

	conf := &oauth2.Config{
		ClientID:     os.Getenv("AUTH0_CLIENT_ID"),
		ClientSecret: os.Getenv("AUTH0_CLIENT_SECRET"),
		RedirectURL:  os.Getenv("AUTH0_CALLBACK_URL"),
		Scopes:       []string{"openid", "profile"},
		Endpoint: oauth2.Endpoint{
			AuthURL:  "https://" + domain + "/authorize",
			TokenURL: "https://" + domain + "/oauth/token",
		},
	}
	state := r.URL.Query().Get("state")
	session, err := store.Get(r, "state")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if state != session.Values["state"] {
		http.Error(w, "Invalid state parameter", http.StatusInternalServerError)
		return
	}

	code := r.URL.Query().Get("code")

	token, err := conf.Exchange(context.TODO(), code)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Getting now the userInfo
	client := conf.Client(context.TODO(), token)
	resp, err := client.Get("https://" + domain + "/userinfo")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	defer resp.Body.Close()

	var profile map[string]interface{}
	if err = json.NewDecoder(resp.Body).Decode(&profile); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	session, err = store.Get(r, "auth-session")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	session.Values["id_token"] = token.Extra("id_token")
	session.Values["access_token"] = token.AccessToken
	session.Values["profile"] = profile
	err = session.Save(r, w)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Redirect to logged in page
	http.Redirect(w, r, "/user", http.StatusSeeOther)
}

// RenderTemplate render template
func RenderTemplate(w http.ResponseWriter, tmpl string, data interface{}) {
	cwd, _ := os.Getwd()
	t, err := template.ParseFiles(filepath.Join(cwd, "./"+tmpl+".html"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	err = t.Execute(w, data)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

// UserHandler handles user information
func UserHandler(w http.ResponseWriter, r *http.Request) {
	session, err := store.Get(r, "auth-session")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	RenderTemplate(w, "user", session.Values["profile"])
}

// IsAuthenticated middleware which check the Authentication
func IsAuthenticated(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {

	session, err := store.Get(r, "auth-session")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if _, ok := session.Values["profile"]; !ok {
		http.Redirect(w, r, "/", http.StatusSeeOther)
	} else {
		next(w, r)
	}
}
