package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
	"github.com/mengkhaiteow/httpserver/internal/auth"
	"github.com/mengkhaiteow/httpserver/internal/database"
)

type apiConfig struct {
	fileserverHits atomic.Int32
	query          *database.Queries
	Platform       string
	jwtSecret string
}

// type chirpResponse struct {
// 	CleanedBody string `json:"cleaned_body"`
// }

type User struct {
	ID        uuid.UUID `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Email     string    `json:"email"`
	Token string `json:"token"`
}

type errorResponse struct {
	Error string `json:"error"`
}

type Chirp struct {
	ID        uuid.UUID `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Body      string    `json:"body"`
	UserID    uuid.UUID `json:"user_id"`
}

func (cfg *apiConfig) middlewareMetricInc(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg.fileserverHits.Add(1)
		next.ServeHTTP(w, r)
	})
}

func (cfg *apiConfig) showHits(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, `<html>
  <body>
    <h1>Welcome, Chirpy Admin</h1>
    <p>Chirpy has been visited %d times!</p>
  </body>
</html>`, cfg.fileserverHits.Load())
}

func (cfg *apiConfig) resetHits(w http.ResponseWriter, r *http.Request) {
	if cfg.Platform != "dev" {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	// reset database
	err := cfg.query.DeleteUsers(r.Context())
	if err != nil {
		log.Printf("Error deleting users: %v", err)
	}

	// reset in memory counter
	cfg.fileserverHits.Store(0)
	w.Header().Add("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Hits reset and database cleared"))
}

func respondWithError(w http.ResponseWriter, code int, msg string) {
	respondWithJSON(w, code, errorResponse{Error: msg})
}

func respondWithJSON(w http.ResponseWriter, code int, payload any) {
	data, err := json.Marshal(payload)
	if err != nil {
		log.Printf("Error marshalling JSON: %s", err)
		w.WriteHeader(500)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	w.Write(data)
}

func getCleanedBody(msg string) string {
	profaneWords := []string{"kerfuffle", "sharbert", "fornax"}
	words := strings.Split(msg, " ")
	cleanedMsg := strings.Split(msg, " ")
	for index, word := range words {
		if slices.Contains(profaneWords, strings.ToLower(word)) {
			cleanedMsg[index] = "****"
		}
	}
	result := strings.Join(cleanedMsg, " ")
	return result
}

func (cfg *apiConfig) handleUser(w http.ResponseWriter, r *http.Request) {
	type parameter struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	decoder := json.NewDecoder(r.Body)
	params := parameter{}
	err := decoder.Decode(&params)
	if err != nil {
		respondWithError(w, 400, "Something went wrong")
		return
	}

	hashedPassword, err := auth.HashPassword(params.Password)
	if err != nil {
		respondWithError(w, 500, "Couldn't hash password")
		return
	}
	user, err := cfg.query.CreateUser(r.Context(), database.CreateUserParams{
		Email:          params.Email,
		HashedPassword: hashedPassword,
	})
	if err != nil {
		log.Printf("Error creating user: %v", err)
		respondWithError(w, 500, "Something went wrong when creating user")
		return
	} else {
		respondWithJSON(w, 201, User{ID: user.ID, CreatedAt: user.CreatedAt, UpdatedAt: user.UpdatedAt, Email: user.Email})
	}
}

func (cfg *apiConfig) handleLogin(w http.ResponseWriter, r *http.Request) {
	type parameter struct {
		Email    string `json:"email"`
		Password string `json:"password"`
		ExpiresInSeconds int `json:"expires_in_seconds"` //Optional
	}

	decoder := json.NewDecoder(r.Body)
	params := parameter{}
	err := decoder.Decode(&params)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "Something went wrong")
		return
	}

	// Handle Expiration Logic
	defaultExpiry := time.Hour
	if params.ExpiresInSeconds > 0 && time.Duration(params.ExpiresInSeconds)*time.Second < defaultExpiry {
		defaultExpiry = time.Duration(params.ExpiresInSeconds) * time.Second
	}

	user, err := cfg.query.GetUserByEmail(r.Context(), params.Email)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "Incorrect email or password")
		return
	}
	match, err := auth.CheckPasswordHash(params.Password, user.HashedPassword)
	if err != nil {
		log.Printf("User password not matched: %v", err)
		respondWithError(w, http.StatusUnauthorized, "Incorrect email or password")
		return
	}
	if !match {
		respondWithError(w, http.StatusUnauthorized, "Incorrect email or password")
		return
	}

	// Create the Token
	token, err := auth.MakeJWT(user.ID, cfg.jwtSecret, defaultExpiry)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Couldn't create token")
		return
	}

	respondWithJSON(w, http.StatusOK, User{ID: user.ID, CreatedAt: user.CreatedAt, UpdatedAt: user.UpdatedAt, Email: user.Email, Token: token})
}

func (cfg *apiConfig) createChirp(w http.ResponseWriter, r *http.Request) {
	// get the token from headers
	token, err := auth.GetBearerToken(r.Header)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "Couldn't find JWT")
		return
	}

	// validate token and extract the user id
	userID, err := auth.ValidateJWT(token, cfg.jwtSecret)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "Couldn't validate JWT")
		return
	}
	type parameter struct {
		Body   string    `json:"body"`
	}

	// move validate_chirp logic here
	decoder := json.NewDecoder(r.Body)
	params := parameter{}
	err = decoder.Decode(&params)
	// old validation logic
	if err != nil {
		respondWithError(w, 500, "Something went wrong")
		return
	}
	if len(params.Body) > 140 {
		respondWithError(w, 400, "Chirp is too long")
		return
	}
	cleanedBody := getCleanedBody(params.Body)

	// database call
	chirp, err := cfg.query.CreateChirp(r.Context(), database.CreateChirpParams{
		Body:   cleanedBody,
		UserID: userID,
	})
	if err != nil {
		log.Printf("Error creating chirp: %v", err)
		respondWithError(w, 500, "Couldn't create chirp")
		return
	}

	respondWithJSON(w, http.StatusCreated, Chirp{
		ID:        chirp.ID,
		CreatedAt: chirp.CreatedAt,
		UpdatedAt: chirp.UpdatedAt,
		Body:      chirp.Body,
		UserID:    chirp.UserID,
	})

}

func (cfg *apiConfig) getChirps(w http.ResponseWriter, r *http.Request) {
	dbchirps, err := cfg.query.GetChirps(r.Context())
	if err != nil {
		log.Printf("Error getting chirp: %v", err)
		respondWithError(w, 500, "Couldn't get chirp")
		return
	}
	chirps := []Chirp{}
	for _, chirp := range dbchirps {
		chirps = append(chirps, Chirp{
			ID:        chirp.ID,
			CreatedAt: chirp.CreatedAt,
			UpdatedAt: chirp.UpdatedAt,
			Body:      chirp.Body,
			UserID:    chirp.UserID,
		})
	}

	respondWithJSON(w, http.StatusOK, chirps)
}

func (cfg *apiConfig) getChirp(w http.ResponseWriter, r *http.Request) {
	chirpIDString := r.PathValue("chirpID")
	chirpID, err := uuid.Parse(chirpIDString)
	if err != nil {
		log.Printf("Invalid chirp ID: %v", err)
		respondWithError(w, 400, "Couldn't parse chirp ID")
		return
	}
	chirp, err := cfg.query.GetChirp(r.Context(), chirpID)
	if err != nil {
		respondWithError(w, 404, "Chirp not found")
		return
	}

	respondWithJSON(w, 200, Chirp{
		ID:        chirp.ID,
		CreatedAt: chirp.CreatedAt,
		UpdatedAt: chirp.UpdatedAt,
		Body:      chirp.Body,
		UserID:    chirp.UserID,
	})

}

func main() {
	godotenv.Load()
	dbURL := os.Getenv("DB_URL")
	db, err := sql.Open("postgres", dbURL)
	err = db.Ping()
	if err != nil {
		log.Fatal("Could not connect to DB:", err)
		return
	}
	dbQueries := database.New(db)
	apiCfg := &apiConfig{
		fileserverHits: atomic.Int32{},
		query:          dbQueries,
		Platform:       os.Getenv("PLATFORM"),
		jwtSecret: os.Getenv("JWT_SECRET"),
	}

	mux := http.NewServeMux()
	server := &http.Server{
		Addr:    ":8080",
		Handler: mux,
	}

	fsHandler := http.FileServer(http.Dir("."))

	wrappedHandler := apiCfg.middlewareMetricInc(fsHandler)

	mux.Handle("/app/", http.StripPrefix("/app/", wrappedHandler))

	mux.HandleFunc("GET /api/healthz", func(w http.ResponseWriter, req *http.Request) {
		w.Header().Add("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		data := []byte("OK")
		w.Write(data)
	})

	mux.HandleFunc("GET /admin/metrics", apiCfg.showHits)
	mux.HandleFunc("POST /admin/reset", apiCfg.resetHits)
	mux.HandleFunc("POST /api/users", apiCfg.handleUser)
	mux.HandleFunc("POST /api/login", apiCfg.handleLogin)
	mux.HandleFunc("POST /api/chirps", apiCfg.createChirp)
	mux.HandleFunc("GET /api/chirps", apiCfg.getChirps)
	mux.HandleFunc("GET /api/chirps/{chirpID}", apiCfg.getChirp)

	server.ListenAndServe()
}
