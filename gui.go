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
	http.HandleFunc("/api/control/checks", guiControlListChecks)
	http.HandleFunc("/api/control/start", guiControlStart)
	http.Handle("/api/results/", resultsWsHandle{upgrader: websocket.Upgrader{}})

	util.OpenBrowser("http://localhost:8080/")

	// start serving
	http.ListenAndServe(":8080", nil)
}

func guiControlStart(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	var b []byte
	if r.Method == http.MethodPost {
		go startChecks()
		b = makeGuiControlResponse(guiResponse{Code: "OK", Message: "Started", Params: nil})
	} else {
		b = makeGuiControlResponse(guiResponse{Code: "ERROR", Message: "Invalid request method", Params: nil})
	}
	fmt.Fprint(w, string(b))
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

	defer func() {
		conn.Close()
	}()

	// here we should listen to the results channel
	for data := range log.AllResults {
		err = conn.WriteMessage(websocket.TextMessage, makeGuiCheckItem(data))
		if err != nil {
			panic(fmt.Sprintf("Error sending message: %v", err))
		}
	}
}
