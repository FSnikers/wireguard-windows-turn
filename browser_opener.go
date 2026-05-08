/* SPDX-License-Identifier: MIT */

package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	neturl "net/url"
	"os/exec"
	"runtime"
)

const browserOpenerPort = "12345"

type BrowserOpener struct {
	server *http.Server
}

func StartBrowserOpener() *BrowserOpener {
	mux := http.NewServeMux()
	mux.HandleFunc("/open-browser", handleOpenBrowserRequest)

	server := &http.Server{
		Addr:    "127.0.0.1:" + browserOpenerPort,
		Handler: mux,
	}

	bo := &BrowserOpener{server: server}

	go func() {
		log.Printf("Browser opener service listening on http://127.0.0.1:%s", browserOpenerPort)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("Browser opener error: %v", err)
		}
	}()

	return bo
}

func (bo *BrowserOpener) Stop() {
	if bo.server != nil {
		bo.server.Close()
	}
}

func handleOpenBrowserRequest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var payload struct {
		URL string `json:"url"`
	}

	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	if payload.URL == "" {
		http.Error(w, "URL is required", http.StatusBadRequest)
		return
	}

	log.Printf("Received request to open URL: %s", payload.URL)

	if err := openBrowserInUserSession(getCleanURL(payload.URL)); err != nil {
		log.Printf("Failed to open browser: %v", err)
		http.Error(w, fmt.Sprintf("Failed to open browser: %v", err), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func openBrowserInUserSession(url string) error {
	switch runtime.GOOS {
	case "windows":
		// Открываем браузер от имени текущего пользователя
		cmd := exec.Command("cmd", "/c", "start", url)
		return cmd.Start()
	default:
		return fmt.Errorf("unsupported OS: %s", runtime.GOOS)
	}
}

func getCleanURL(rawURL string) string {
	parsed, err := neturl.Parse(rawURL)
	if err != nil {
		return rawURL
	}

	// Возвращаем только схему и хост
	return fmt.Sprintf("%s://%s", parsed.Scheme, parsed.Host)
}
