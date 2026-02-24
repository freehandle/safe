package safe

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/freehandle/breeze/crypto"
)

// const msgConfirmation = `http://%s/confirm/%s`

type RestAPI struct {
	Safe *Safe
}

type AttorneyRequest struct {
	Handle        string `json:"handle"`
	AttorneyToken string `json:"attorney_token"`
}

type UserRequest struct {
	Handle        string `json:"handle"`
	Email         string `json:"email,omitempty"`
	Password      string `json:"password,omitempty"`
	AttorneyToken string `json:"attorney_token"`
	App           string `json:"app,omitempty"`
}

/*type GrantRequest struct {
	Handle        string `json:"handle"`
	AttorneyToken string `json:"attorney_token"`
	Hash          string `json:"hash"`
}
*/

type APIResponse struct {
	Status  string `json:"status"`
	Message string `json:"message,omitempty"`
	Token   string `json:"token,omitempty"`
	Verify  string `json:"verify,omitempty"`
}

func (rest *RestAPI) userExists(handle string) bool {
	// Verificar se o usuário existe tentando criar uma sessão
	// Se retornar string vazia, o usuário não existe
	session := rest.Safe.CreateSession(handle)
	return session != ""
}

/*func (rest *RestAPI) userEmail(handle string) string {
	return rest.Safe.Email(handle)
}*/

func (rest *RestAPI) userEmailAndToken(handle string) (string, crypto.Token) {
	return rest.Safe.EmailAndToken(handle)
}

func (rest *RestAPI) handleAttorneyAPI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(APIResponse{
			Status:  "error",
			Message: "Only POST method is allowed",
		})
		return
	}
	var req AttorneyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(APIResponse{
			Status:  "error",
			Message: "Invalid JSON format",
		})
		return
	}
	if req.Handle == "" || (!rest.userExists(req.Handle)) {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(APIResponse{
			Status:  "error",
			Message: "Invalid user handle",
		})
		return
	}
	attorneys := rest.Safe.UserAttorneys(req.Handle)
	granted := false
	for _, attorney := range attorneys {
		if req.AttorneyToken == attorney.String() {
			granted = true
			break
		}
	}
	email, token := rest.Safe.EmailAndToken(req.Handle)
	response := APIResponse{
		Message: email,
		Token:   token.String(),
	}
	if granted {
		response.Status = "Granted"
	} else {
		response.Status = "Not Granted"
	}
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

func (rest *RestAPI) handleAPI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(APIResponse{
			Status:  "error",
			Message: "Only POST method is allowed",
		})
		return
	}

	var req UserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(APIResponse{
			Status:  "error",
			Message: "Invalid JSON format",
		})
		return
	}

	if req.Handle == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(APIResponse{
			Status:  "error",
			Message: "Handle is required",
		})
		return
	}

	// Verificar se o handle já existe no safe
	if rest.userExists(req.Handle) {
		token, _ := crypto.RandomAsymetricKey()
		secret := token.Hex()
		msg := fmt.Sprintf("http://%s/confirm/%s", rest.Safe.address, secret)
		if rest.Safe.serverName != "" {
			msg = fmt.Sprintf("http://%s/%sconfirm/%s", rest.Safe.address, rest.Safe.serverName, secret)
		}
		grant := rest.Safe.GrantAction(req.Handle, req.AttorneyToken)
		rest.Safe.NewPending(secret, grant)
		w.WriteHeader(http.StatusOK)
		email, token := rest.userEmailAndToken(req.Handle)
		json.NewEncoder(w).Encode(APIResponse{
			Status:  "existente",
			Message: email,
			Token:   token.String(),
			Verify:  msg,
		})
		return
	}

	// Se não existe, criar novo usuário
	// Usar valores padrão se email ou password não fornecidos
	email := req.Email
	password := req.Password
	if password == "" {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(APIResponse{
			Status:  "error",
			Message: "Senha não especificada para usuário novo",
		})
		return
	}
	// Tentar criar o usuário
	success, token := rest.Safe.SigninWithToken(req.Handle, password, email)
	if !success {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(APIResponse{
			Status:  "error",
			Message: "Failed to create user",
		})
		return
	}
	hashToken := crypto.EncodeHash(crypto.HashToken(token))
	if err := rest.Safe.GrantPower(req.Handle, req.AttorneyToken, hashToken); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(APIResponse{
			Status:  "error",
			Message: "User created but failed to grant power of attorney: " + err.Error(),
		})
		return
	}
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(APIResponse{
		Status:  "criado",
		Message: "Usuário criado com sucesso e power of attorney concedido",
		Token:   token.String(),
	})
}

func NewSafeRestAPI(port int, safe *Safe) {
	mux := http.NewServeMux()
	rest := RestAPI{Safe: safe}
	mux.HandleFunc("/", rest.handleAPI)
	mux.HandleFunc("/attorney", rest.handleAttorneyAPI)
	srv := &http.Server{
		Addr:         fmt.Sprintf(":%v", port),
		Handler:      mux,
		WriteTimeout: 2 * time.Second,
	}
	fmt.Println("Safe REST API server started on port", port)
	srv.ListenAndServe()
}
