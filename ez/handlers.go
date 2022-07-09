/*
Copyright © 2022 THINKINGATOMS LLC <atom@thinkingatoms.com>
*/

package ez

import (
	"encoding/json"
	"fmt"
	"github.com/rs/zerolog/hlog"
	"net/http"
)

func InternalServerErrorHandler(w http.ResponseWriter, r *http.Request, err error) {
	_ = r
	w.WriteHeader(http.StatusInternalServerError)
	_, _ = fmt.Fprintln(w, "internal server error:  "+err.Error())
	hlog.FromRequest(r).Error().Err(err).Msg("internal server error")
}

func BadRequestHandler(w http.ResponseWriter, r *http.Request, err error) {
	_ = r
	w.WriteHeader(http.StatusBadRequest)
	_, _ = fmt.Fprintln(w, "bad request:  "+err.Error())
	hlog.FromRequest(r).Error().Err(err).Msg("bad request")
}

func AccessDeniedHandler(w http.ResponseWriter, r *http.Request, err error) {
	_ = r
	w.WriteHeader(http.StatusUnauthorized)
	_, _ = fmt.Fprintln(w, "unauthorized:  "+err.Error())
	hlog.FromRequest(r).Error().Err(err).Msg("forbidden")
}

func WriteObjectAsJSON(w http.ResponseWriter, r *http.Request, v any) {
	marshal, err := json.Marshal(v)
	if err != nil {
		InternalServerErrorHandler(w, r, err)
		return
	}
	_, err = w.Write(marshal)
	if err != nil {
		InternalServerErrorHandler(w, r, err)
		return
	}
}

func WriteBytes(w http.ResponseWriter, r *http.Request, marshal []byte) {
	_, err := w.Write(marshal)
	if err != nil {
		InternalServerErrorHandler(w, r, err)
		return
	}
}

func StaticMsgHandler(msg string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		_ = r
		_, _ = w.Write([]byte(msg))
	}
}

type DummyResponseWriter struct {
	header     map[string][]string
	StatusCode int
}

func (self *DummyResponseWriter) Header() http.Header {
	return self.header
}

func (self *DummyResponseWriter) Write(b []byte) (int, error) {
	return len(b), nil
}

func (self *DummyResponseWriter) WriteHeader(statusCode int) {
	self.StatusCode = statusCode
}

func GetDummyResponseWriter() *DummyResponseWriter {
	return &DummyResponseWriter{
		header:     make(map[string][]string),
		StatusCode: http.StatusOK,
	}
}

func _() {
	_ = StaticMsgHandler
}
