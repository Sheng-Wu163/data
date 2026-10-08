// Package api exposes the fingerprint engine over HTTP.
package api

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/Sheng-Wu163/data/internal/fingerprint"
	"github.com/Sheng-Wu163/data/internal/model"
)

// maxBodyBytes bounds request size to protect the service from oversized or
// malicious payloads.
const maxBodyBytes = 8 << 20 // 8 MiB

// Handler wires the HTTP endpoints to a fingerprint engine.
type Handler struct {
	engine *fingerprint.Engine
}

// New returns a Handler backed by engine.
func New(engine *fingerprint.Engine) *Handler {
	return &Handler{engine: engine}
}

// Handler returns the fully-wrapped http.Handler for the service.
func (h *Handler) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", h.health)
	mux.HandleFunc("/fingerprint", h.fingerprint)
	return h.withLogging(mux)
}

func (h *Handler) health(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status": "ok",
		"rules":  h.engine.RuleCount(),
		"time":   time.Now().UTC().Format(time.RFC3339),
	})
}

func (h *Handler) fingerprint(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed, use POST")
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBodyBytes))
	if err != nil {
		writeError(w, http.StatusRequestEntityTooLarge, "request body too large or unreadable")
		return
	}
	items, err := model.ParseInputs(body)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, h.engine.IdentifyAll(items))
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

func (h *Handler) withLogging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		log.Printf("%s %s -> %d (%s)", r.Method, r.URL.Path, rec.status, time.Since(start))
	})
}
