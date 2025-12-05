package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

func isIpValid(site string, ip string, keyName string, value string) bool {
	request := strings.Builder{}
	request.WriteString(site)
	request.WriteString(ip)
	resp, err := http.Get(request.String())
	if err != nil {
		fmt.Println("Unable to connect to ip checker server:", err)
		return false
	} else if resp.StatusCode == 200 {
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			fmt.Println("Unable to read ip info:", err)
			return false
		} else {
			var answer map[string]interface{}
			err := json.Unmarshal([]byte(body), &answer)
			if err != nil {
				fmt.Println("Ошибка при разборе JSON:", err)
				return false
			}
			for key, val := range answer {
				if key == keyName {
					if val == value {
						return false
					} else {
						fmt.Println("Country ", val)
						return true
					}
				}
			}
		}
	} else {
		fmt.Println("Service unavailable :", err)
	}
	return false
}
