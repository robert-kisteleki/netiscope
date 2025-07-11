package main

import (
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"netiscope/log"
	"netiscope/util"

	"github.com/gorilla/websocket"
)

//go:embed assets
var embeddedFS embed.FS

type guiResponse struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Params  any    `json:"params,omitempty"`
}

func runGui() {
	// "assets" is where static stuff goes to, but it's served with HTTP under /
	serverRoot, err := fs.Sub(embeddedFS, "assets")
	if err != nil {
		panic(err)
	}

	// define the paths we serve: static, API, WS
	http.Handle("/", http.FileServer(http.FS(serverRoot)))
	http.HandleFunc("/api/version", guiControlGetVersion)
	http.HandleFunc("/api/control/checks", guiControlListChecks)
	http.HandleFunc("/api/control/start", guiControlStart)
	http.Handle("/api/results/", resultsWsHandle{upgrader: websocket.Upgrader{}})

	util.OpenBrowser("http://localhost:8080/")

	// start serving
	http.ListenAndServe(":8080", nil)
}

func guiControlGetVersion(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	b := makeGuiControlResponse(guiResponse{Code: "OK", Message: "OK", Params: util.Version})
	fmt.Fprint(w, string(b))
}

func guiControlStart(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	type RequestData struct {
		Checks []string `json:"checks"`
		IPv4   bool     `json:"ipv4"`
		IPv6   bool     `json:"ipv6"`
	}

	if r.Method != http.MethodPost {
		http.Error(w, "Invalid method", http.StatusBadRequest)
		return
	}

	var data RequestData
	err := json.NewDecoder(r.Body).Decode(&data)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	util.GuiIPv4 = data.IPv4
	util.GuiIPv6 = data.IPv6
	go startChecks(data.Checks, false)

	fmt.Fprint(w, string(
		makeGuiControlResponse(guiResponse{Code: "OK", Message: "Started", Params: nil})),
	)
}

func guiControlListChecks(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	checks := util.GetChecks()
	b := makeGuiControlResponse(guiResponse{Code: "OK", Message: "", Params: checks})
	fmt.Fprint(w, string(b))
}

func makeGuiControlResponse(response guiResponse) []byte {
	b, err := json.Marshal(response)
	if err != nil {
		panic(err)
	}
	return b
}

func makeGuiCheckItem(item log.ResultItem) []byte {
	b, err := json.Marshal(item)
	if err != nil {
		panic(err)
	}
	return b
}

// WebSocket stuff
type resultsWsHandle struct {
	upgrader websocket.Upgrader
}

// here's where the actual WebSocket handler code is
func (wsh resultsWsHandle) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	conn, err := wsh.upgrader.Upgrade(w, r, nil)
	if err != nil {
		panic(fmt.Sprintf("Error %s when upgrading connection to websocket", err))
	}

	defer conn.Close()

	// here we should listen to the results channel
	for data := range log.AllResults {
		err = conn.WriteMessage(websocket.TextMessage, makeGuiCheckItem(data))
		if err != nil {
			panic(fmt.Sprintf("Error sending message: %v", err))
		}
	}
}
