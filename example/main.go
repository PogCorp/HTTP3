package main

import (
	"flag"
	"log"
	"net/http"
	"poghttp3/pkg/http3/quicgo"
	"time"
)

func main() {

	cert := flag.String("c", "", "/path/to/certificate.crt")
	key := flag.String("k", "", "/path/to/private.key")

	flag.Parse()

	if *cert == "" {
		log.Fatalln("certificate not provided")
	}

	if *key == "" {
		log.Fatalln("key not provided")
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		tm := time.Now().Format(time.RFC1123)
		_, err := w.Write([]byte("The time is: " + tm))
		if err != nil {
			log.Println("unble to write response")
		}
		w.WriteHeader(200)
	})

	if err := quicgo.ListenAndServeTLS(
		"localhost:8080",
		*cert,
		*key,
		mux,
	); err != nil {
		log.Printf("server failed, got err: %s", err)
	}
}
