package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
)

type importantStuff struct {
	Whatpoint string `json:"what_point"`
}

func main() {
	flag, err := os.ReadFile("flag.txt")
	if err != nil {
		panic(err)
	}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			fmt.Fprint(w, "Hello, world")
			return
		case http.MethodPost:
			body, err := io.ReadAll(r.Body)
			if err != nil {
				fmt.Fprintf(w, "error 1")
				return
			}

			if strings.Contains(string(body), "what_point") || strings.Contains(string(body), "\\") {
				fmt.Fprintf(w, string(body))
				fmt.Fprintf(w, "bypass 1")
				return
			}

			var whatpoint importantStuff
			err = json.Unmarshal(body, &whatpoint)
			if err != nil {
				fmt.Fprintf(w, "error 2 not json format")
				return
			}

			// fmt.Fprintf(w, string(body))
			fmt.Fprintln(w, whatpoint.Whatpoint)

			if whatpoint.Whatpoint == "that_point" {
				fmt.Fprintf(w, "Congrats! Here is the flag: %s", flag)
				return
			} else {
				fmt.Fprintf(w, string(body))
				fmt.Fprintf(w, "bypass 2 error")
				return
			}
		default:
			fmt.Fprint(w, "Method not allowed")
			return
		}
	})

	log.Fatal(http.ListenAndServe(":8081", nil))

}
