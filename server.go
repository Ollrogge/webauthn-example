package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"strings"

	"github.com/duo-labs/webauthn.io/session"
	"github.com/duo-labs/webauthn/protocol"
	"github.com/duo-labs/webauthn/webauthn"
	"github.com/gorilla/mux"
)

var webAuthn *webauthn.WebAuthn
var userDB *userdb
var sessionStore *session.Store

type CredentialAssertion struct {
	Response PublicKeyCredentialRequestOptions `json:"publicKey"`
}

type PublicKeyCredentialRequestOptions struct {
	Challenge      protocol.Challenge `json:"challenge"`
	Timeout        int                `json:"timeout,omitempty"`
	RelyingPartyID string             `json:"rpId,omitempty"`
	//AllowedCredentials []CredentialDescriptor               `json:"allowCredentials,omitempty"`
	AllowedCredentials []CredentialDescriptor               `json:"-"`                          // Ignore because allowlist is optional and we are optimizing for small size
	UserVerification   protocol.UserVerificationRequirement `json:"userVerification,omitempty"` // Default is "preferred"
	Extensions         protocol.AuthenticationExtensions    `json:"extensions,omitempty"`
}

type CredentialDescriptor struct {
	// The valid credential types.
	Type protocol.CredentialType `json:"type"`
	// CredentialID The ID of a credential to allow/disallow
	CredentialID []byte `json:"id"`
	// The authenticator transports that can be used
	Transport []protocol.AuthenticatorTransport `json:"transports,omitempty"`
	PublicKey []byte                            `json:"publicKey,omitempty"`
}

type resp struct {
	status string
}

func (p *CredentialAssertion) Unmarshal(
	data *protocol.CredentialAssertion,
	userCreds []webauthn.Credential) error {
	p.Response.Challenge = data.Response.Challenge
	p.Response.Timeout = data.Response.Timeout
	p.Response.RelyingPartyID = data.Response.RelyingPartyID
	p.Response.UserVerification = data.Response.UserVerification
	p.Response.Extensions = data.Response.Extensions

	var allowedCreds []CredentialDescriptor

	for _, v := range data.Response.AllowedCredentials {
		for _, v2 := range userCreds {
			if bytes.Equal(v.CredentialID, v2.ID) {
				allowedCreds = append(allowedCreds, CredentialDescriptor{
					Type:         v.Type,
					CredentialID: v.CredentialID,
					Transport:    v.Transport,
					PublicKey:    v2.PublicKey,
				})
			}
		}
	}

	/* hopefully sort by most recently registered */
	/*
		for i := 1; i < len(allowedCreds)/2; i++ {
			var tmp = allowedCreds[i]
			allowedCreds[i] = allowedCreds[len(allowedCreds)-0x1-i]
			allowedCreds[len(allowedCreds)-0x1-i] = tmp
		}
	*/

	p.Response.AllowedCredentials = allowedCreds

	return nil
}

func main() {
	var err error
	webAuthn, err = webauthn.New(&webauthn.Config{
		RPDisplayName: "Fido2 + LoRa test.",    // Display Name for your site
		RPID:          "localhost",             // Generally the domain name for your site
		RPOrigin:      "http://localhost:8010", // The origin URL for WebAuthn requests
		// RPIcon: "https://duo.com/logo.png", // Optional icon URL for your site
	})

	if err != nil {
		log.Fatal("failed to create WebAuthn from config:", err)
	}

	userDB = DB()

	sessionStore, err = session.NewStore()
	if err != nil {
		log.Fatal("failed to create session store:", err)
	}

	r := mux.NewRouter()

	r.HandleFunc("/register/begin/{username}", BeginRegistration).Methods("GET")
	r.HandleFunc("/register/finish/{username}", FinishRegistration).Methods("POST")
	r.HandleFunc("/login/begin/{username}", BeginLogin).Methods("GET")
	r.HandleFunc("/login/finish/{username}", FinishLogin).Methods("POST")

	r.PathPrefix("/").Handler(http.FileServer(http.Dir("./")))

	serverAddress := ":8010"
	log.Println("starting server at", serverAddress)
	log.Fatal(http.ListenAndServe(serverAddress, r))
}

func print_req(r *http.Request) {
	res, err := httputil.DumpRequest(r, true)
	if err != nil {
		log.Fatal(err)
	}
	log.Println(string(res))
}

func BeginRegistration(w http.ResponseWriter, r *http.Request) {
	log.Println("Register start")
	print_req(r)

	// get username/friendly name
	vars := mux.Vars(r)
	username, ok := vars["username"]
	if !ok {
		jsonResponse(w, fmt.Errorf("must supply a valid username i.e. foo@bar.com"), http.StatusBadRequest)
		return
	}

	// get user
	user, err := userDB.GetUser(username)
	// user doesn't exist, create new user
	if err != nil {
		displayName := strings.Split(username, "@")[0]
		user = NewUser(username, displayName)
		userDB.PutUser(user)
	}

	var rk bool = true

	registerOptions := func(credCreationOpts *protocol.PublicKeyCredentialCreationOptions) {
		credCreationOpts.CredentialExcludeList = user.CredentialExcludeList()
		// default want resident key
		credCreationOpts.AuthenticatorSelection.RequireResidentKey = &rk
		credCreationOpts.AuthenticatorSelection.UserVerification = protocol.VerificationDiscouraged
	}

	// generate PublicKeyCredentialCreationOptions, session data
	options, sessionData, err := webAuthn.BeginRegistration(
		user,
		registerOptions,
	)

	if err != nil {
		log.Println(err)
		jsonResponse(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// store session data as marshaled JSON
	err = sessionStore.SaveWebauthnSession("registration", sessionData, r, w)
	if err != nil {
		log.Println(err)
		jsonResponse(w, err.Error(), http.StatusInternalServerError)
		return
	}

	jsonResponse(w, options, http.StatusOK)
}

func FinishRegistration(w http.ResponseWriter, r *http.Request) {
	log.Println("Register finish")
	print_req(r)
	// get username
	vars := mux.Vars(r)
	username := vars["username"]

	// get user
	user, err := userDB.GetUser(username)
	// user doesn't exist
	if err != nil {
		log.Println("Error: ", err)
		jsonResponse(w, err.Error(), http.StatusBadRequest)
		return
	}

	// load the session data
	sessionData, err := sessionStore.GetWebauthnSession("registration", r)
	if err != nil {
		log.Println("Error: ", err)
		jsonResponse(w, err.Error(), http.StatusBadRequest)
		return
	}

	credential, err := webAuthn.FinishRegistration(user, sessionData, r)
	if err != nil {
		log.Println("Error: ", err)
		jsonResponse(w, err.Error(), http.StatusBadRequest)
		return
	}

	user.AddCredential(*credential)

	var resp resp
	resp.status = "Registration Success"

	jsonResponse(w, resp, http.StatusOK)
}

func BeginLogin(w http.ResponseWriter, r *http.Request) {
	log.Println("Login begin")
	print_req(r)
	// get username
	vars := mux.Vars(r)
	username := vars["username"]

	// get user
	user, err := userDB.GetUser(username)
	// user doesn't exist
	if err != nil {
		log.Println(err)
		jsonResponse(w, err.Error(), http.StatusBadRequest)
		return
	}

	log.Println("User: ", user)

	pub_key := user.credentials[0].PublicKey
	if len(pub_key) == 0 {
		jsonResponse(w, "credential error", http.StatusInternalServerError)
		return
	}

	// generate PublicKeyCredentialRequestOptions, session data
	options, sessionData, err := webAuthn.BeginLogin(user)
	if err != nil {
		log.Println("webauthn.BeginLogin failed: ", err)
		jsonResponse(w, err.Error(), http.StatusInternalServerError)
		return
	}

	var myOptions CredentialAssertion
	err = myOptions.Unmarshal(options, user.credentials)
	if err != nil {
		log.Println(err)
		jsonResponse(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// store session data as marshaled JSON
	err = sessionStore.SaveWebauthnSession("authentication", sessionData, r, w)
	if err != nil {
		log.Println(err)
		jsonResponse(w, err.Error(), http.StatusInternalServerError)
		return
	}

	jsonResponse(w, &myOptions, http.StatusOK)
}

func FinishLogin(w http.ResponseWriter, r *http.Request) {
	log.Println("Login finish")
	print_req(r)

	// get username
	vars := mux.Vars(r)
	username := vars["username"]

	// get user
	user, err := userDB.GetUser(username)

	// user doesn't exist
	if err != nil {
		log.Println(err)
		jsonResponse(w, err.Error(), http.StatusBadRequest)
		return
	}

	// load the session data
	sessionData, err := sessionStore.GetWebauthnSession("authentication", r)
	if err != nil {
		log.Println(err)
		jsonResponse(w, err.Error(), http.StatusBadRequest)
		return
	}

	log.Println("User: ", user.credentials)

	// in an actual implementation, we should perform additional checks on
	// the returned 'credential', i.e. check 'credential.Authenticator.CloneWarning'
	// and then increment the credentials counter
	_, err = webAuthn.FinishLogin(user, sessionData, r)
	if err != nil {
		log.Println(err)
		jsonResponse(w, err.Error(), http.StatusBadRequest)
		return
	}

	// handle successful login
	jsonResponse(w, "Login Success", http.StatusOK)
}

// from: https://github.com/duo-labs/webauthn.io/blob/3f03b482d21476f6b9fb82b2bf1458ff61a61d41/server/response.go#L15
func jsonResponse(w http.ResponseWriter, d interface{}, c int) {
	dj, err := json.Marshal(d)
	if err != nil {
		http.Error(w, "Error creating JSON response", http.StatusInternalServerError)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(c)
	fmt.Fprintf(w, "%s", dj)
}
