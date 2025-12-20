package main

import (
	"net/http"
)


func main(){
	mux := http.NewServeMux()
	server := &http.Server{
		Addr: ":8080",
		Handler: mux,
	}

	mux.Handle("/app/",http.StripPrefix("/app/",http.FileServer(http.Dir("."))))
	mux.HandleFunc("/healthz",func(w http.ResponseWriter, req *http.Request){
		w.Header().Add("Content-Type","text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		data := []byte("OK")
		w.Write(data)
	})

	server.ListenAndServe()
}
