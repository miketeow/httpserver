package main

import (
	"fmt"
	"net/http"
	"sync/atomic"
)

type apiConfig struct {
	fileserverHits atomic.Int32
}

func (cfg *apiConfig) middlewareMetricInc(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg.fileserverHits.Add(1)
		next.ServeHTTP(w,r)
	})
}

func (cfg *apiConfig) showHits(w http.ResponseWriter, r *http.Request){
	w.Header().Add("Content-Type","text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w,"Hits: %d", cfg.fileserverHits.Load())
}

func (cfg *apiConfig) resetHits(w http.ResponseWriter, r *http.Request){
	w.Header().Add("Content-Type","text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	cfg.fileserverHits.Swap(0)
}


func main(){
	apiCfg := &apiConfig{
		fileserverHits: atomic.Int32{},
	}

	mux := http.NewServeMux()
	server := &http.Server{
		Addr: ":8080",
		Handler: mux,
	}

	fsHandler := http.FileServer(http.Dir("."))

	wrappedHandler := apiCfg.middlewareMetricInc(fsHandler)

	mux.Handle("/app/",http.StripPrefix("/app/",wrappedHandler))

	mux.HandleFunc("GET /healthz",func(w http.ResponseWriter, req *http.Request){
		w.Header().Add("Content-Type","text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		data := []byte("OK")
		w.Write(data)
	})

	mux.HandleFunc("GET /metrics", apiCfg.showHits)
	mux.HandleFunc("POST /reset", apiCfg.resetHits)

	server.ListenAndServe()
}
