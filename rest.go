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

type APIResponse struct {
	Status  string `json:"status"`
	Message string `json:"message,omitempty"`
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
	success, _ := rest.Safe.SigninWithToken(req.Handle, password, email)
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
	})
}

func NewSafeRestAPI(port int, safe *Safe) {
	mux := http.NewServeMux()
	rest := RestAPI{Safe: safe}
	mux.HandleFunc("/", rest.handleAPI)
	srv := &http.Server{
		Addr:         fmt.Sprintf(":%v", port),
		Handler:      mux,
		WriteTimeout: 2 * time.Second,
	}
	srv.ListenAndServe()
}
