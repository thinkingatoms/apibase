/*
Copyright © 2022 THINKINGATOMS LLC <atom@thinkingatoms.com>
*/

package servers

import (
	"fmt"
	"github.com/rs/zerolog/log"
	"net/http"
	"strconv"
	"strings"
)

func wrapHandler(h http.Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		srw := &statusResponseWriter{ResponseWriter: w}
		h.ServeHTTP(srw, r)
		if srw.status >= 400 { // 400+ codes are the error codes
			log.Printf("Error status code: %d when serving path: %s",
				srw.status, r.RequestURI)
		}
	}
}

type statusResponseWriter struct {
	http.ResponseWriter // We embed http.ResponseWriter
	status              int
}

func (w *statusResponseWriter) WriteHeader(status int) {
	w.status = status // Store the status for our own use
	w.ResponseWriter.WriteHeader(status)
}

func ServeStaticFiles(port int, mappings []string) {
	fmt.Println(port, mappings)
	if len(mappings) == 0 {
		panic("No mappings specified")
	}
	for _, mapping := range mappings {
		if mapping == "" {
			panic("Empty mapping specified")
		}
		parts := strings.Split(mapping, ":")
		if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
			panic("Invalid mapping specified: " + mapping)
		}
		if parts[0][0] != '/' {
			panic("Invalid mapping specified: " + mapping)
		}
		if parts[0][len(parts[0])-1] != '/' {
			// StripPrefix doesn't work on directories without the trailing slash
			parts[0] += "/"
		}
		fmt.Println(parts[0], parts[1])
		fs := http.FileServer(http.Dir(parts[1]))
		if parts[0] != "/" {
			fs = http.StripPrefix(parts[0], fs)
		}
		http.Handle(parts[0], wrapHandler(fs))
	}
	err := http.ListenAndServe("0.0.0.0:"+strconv.Itoa(port), nil)
	if err != nil {
		log.Fatal().Err(err).Msg("static file server failed")
	}
}
