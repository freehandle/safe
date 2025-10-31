package safe

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

type RestAPI struct {
	Safe *Safe
}

type UserRequest struct {
	Handle   string `json:"handle"`
	Email    string `json:"email,omitempty"`
	Password string `json:"password,omitempty"`
}

type GrantRequest struct {
	Handle        string `json:"handle"`
	AttorneyToken string `json:"attorney_token"`
	Hash          string `json:"hash"`
}

type APIResponse struct {
	Status  string `json:"status"`
	Message string `json:"message,omitempty"`
	Token   string `json:"token,omitempty"`
}

func (rest *RestAPI) userExists(handle string) bool {
	// Verificar se o usuário existe tentando criar uma sessão
	// Se retornar string vazia, o usuário não existe
	session := rest.Safe.CreateSession(handle)
	return session != ""
}

func (rest *RestAPI) userEmail(handle string) string {
	return rest.Safe.Email(handle)
}

func (rest *RestAPI) handleGrantAPI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(APIResponse{
			Status:  "error",
			Message: "Only POST method is allowed",
		})
		return
	}
	var req GrantRequest
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
	if err := rest.Safe.GrantPower(req.Handle, req.AttorneyToken, req.Hash); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(APIResponse{
			Status:  "error",
			Message: "Failed to grant power of attorney: " + err.Error(),
		})
		return
	}
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(APIResponse{
		Status:  "success",
		Message: "Power of attorney granted successfully",
	})
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
		w.WriteHeader(http.StatusOK)
		email := rest.userEmail(req.Handle)
		json.NewEncoder(w).Encode(APIResponse{
			Status:  "existente",
			Message: email,
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

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(APIResponse{
		Status:  "criado",
		Message: "Usuário criado com sucesso",
		Token:   token.String(),
	})
}

func NewSafeRestAPI(port int, safe *Safe) {
	mux := http.NewServeMux()
	rest := RestAPI{Safe: safe}
	mux.HandleFunc("/", rest.handleAPI)
	mux.HandleFunc("/grant", rest.handleGrantAPI)
	srv := &http.Server{
		Addr:         fmt.Sprintf(":%v", port),
		Handler:      mux,
		WriteTimeout: 2 * time.Second,
	}
	fmt.Println("Safe REST API server started on port", port)
	srv.ListenAndServe()
}
