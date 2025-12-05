package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"
)

type XrVmessServerConfig struct {
	Vmess []VmessServerConfig `json:"vnext"`
}

type VmessServerConfig struct {
	Address string      `json:"address"`
	Port    int         `json:"port"`
	Users   []VmessUser `json:"users"`
}

type VmessUser struct {
	Id string `json:"id"`
	//AlterId string `json:"alterId"` // for v2fly
	Security string `json:"security,omitempty"`
	Level    int    `json:"level,omitempty"`
}

func decodeVmessServerConfig(str string) bool {
	data, err := base64.StdEncoding.DecodeString(str)
	if err != nil {
		fmt.Println("error:", err)
		return false
	}
	datastr := string(data[:])
	errstr := createVmessServerConfig(datastr)
	if errstr != "" {
		fmt.Println(errstr)
		return false
	}
	return true
}

func createVmessServerConfig(str string) (errstr string) {
	var params map[string]any
	err := json.Unmarshal([]byte(str), &params)
	if err != nil {
		fmt.Println("Error unmarshaling JSON vmess:", err)
		return
	}
	if len(params) > 0 {
		conf := new(VmessServerConfig)
		conf.Address = params["add"].(string)
		//check ip
		if !isIpValid(config.IpCheckServer, conf.Address, config.IpCheckKey, config.IpCheckValue) {
			return "Ip is invalid"
		}
		//
		switch t := params["port"].(type) {
		case float64:
			conf.Port = int(t)
		case string:
			i, err := strconv.Atoi(t)
			if err != nil {
				return "Cannot convert vmess port"
			} else {
				conf.Port = i
			}
		default:
			return "Invalid format of vmess port"
		}
		user := new(VmessUser)
		user.Id = params["id"].(string)
		scy, ok := params["scy"].(string)
		if ok && len(scy) > 0 {
			user.Security = scy
		}
		conf.Users = append(conf.Users, *user)
		streamSettings := new(XrStreamSettings)
		netType, ok := params["net"].(string)
		if ok && len(netType) > 0 {
			streamSettings.Network = netType
			switch netType {
			case "tcp":
				streamSettings.Network = "tcp"
			case "ws":
				streamSettings.Network = "ws"
				path, ok := params["path"].(string)
				if ok && len(path) > 0 {
					//check path
					wspar := new(XrWsSettings)
					wspar.Path = path
					streamSettings.WsSettings = *wspar
				}
			}
		}
		tls, ok := params["tls"].(string)
		if ok && len(tls) > 0 {
			streamSettings.Security = "tls"
			host, ok := params["host"].(string)
			tlsSet := new(XrTlsSettings)
			if ok && len(host) > 0 {
				tlsSet.ServerName = host
			}
			fp, ok := params["fp"].(string)
			if ok && len(fp) > 0 {
				tlsSet.ServerName = fp
			}
		}
		xrconf := new(XrayConf)
		xrconf.Protocol = "vmess"
		servers := new(XrVmessServerConfig)
		servers.Vmess = append(servers.Vmess, *conf)
		xrconf.Settings = servers
		xrconf.StreamSet = *streamSettings
		confToSave++
		xrconf.Tag = config.Tag + strconv.Itoa(confToSave) //config.VmessTag + strconv.Itoa(len(xrVmConfigs)+1)
		xrVmConfigs = append(xrVmConfigs, *xrconf)
		vmessConfToSave = vmessConfToSave + 1
	}
	return ""
}
