package checks

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

func MakeHttpGetRequest(url string, timeout int) (string, error) {
	//fmt.Println("Making a HTTP GET request to:", url)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", err
	}
	client := &http.Client{
		Timeout: time.Duration(timeout) * time.Millisecond,
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return string(body), nil
}

func MakeAnchorHttpRequest(anchor string, padding string, payload int, timeout int) (string, error) {
	urlnopad := "http://" + anchor + "/"
	if payload > 0 {
		urlnopad += fmt.Sprintf("%d", payload)
	}
	url := urlnopad
	if padding != "" {
		urlnopad += "?padding="
		url = urlnopad + padding
		urlnopad += fmt.Sprintf("[%d bytes padding]", len(padding))
	}
	res, err := MakeHttpGetRequest(url, timeout)
	if err != nil {
		return res, fmt.Errorf("%s", strings.Replace(err.Error(), url, urlnopad, -1))
	} else {
		type anchorResponse struct {
			Anchor  string `json:"anchor"`
			Client  string `json:"client"`
			Payload string `json:"payload"`
		}
		var rjson anchorResponse
		err := json.Unmarshal([]byte(res), &rjson)
		if err != nil {
			return res, fmt.Errorf("Failed to parse response from anchor %s: %v", anchor, err)
		}
		rjson.Payload = fmt.Sprintf("[%d bytes]", len(rjson.Payload))
		modifiedResponse, err := json.Marshal(rjson)
		if err != nil {
			return res, fmt.Errorf("Failed to marshal modified response from anchor %s: %v", anchor, err)
		}
		return string(modifiedResponse), nil
	}
}
