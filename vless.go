package main

import (
	"fmt"
	"strconv"
	"strings"
)

type XrVlessServerConfig struct {
	Vless []VlessServerConfig `json:"vnext"`
}

type VlessServerConfig struct {
	Address string      `json:"address"`
	Port    int         `json:"port"`
	Users   []VlessUser `json:"users"`
}

type VlessUser struct {
	Id         string `json:"id"`
	Encryption string `json:"encryption"`
	Flow       string `json:"flow,omitempty"`
	Level      int    `json:"level,omitempty"`
}

func decodeVlessServerConfig(str string) bool {
	var uid_ser string
	var params string
	index := strings.IndexByte(str, '?')
	if index == -1 { // no params
		index = strings.IndexByte(str, '@')
		if index == -1 {
			fmt.Println("Can not decode config")
			return false
		} else {
			uid_ser = str
			params = ""
		}
	} else {
		uid_ser = str[:index]
		params = str[index+1:]
	}
	errstr := createVlessServerConfig(uid_ser, params)
	if errstr != "" {
		fmt.Println(errstr)
		return false
	}
	return true
}

func createVlessServerConfig(uid_ser string, params string) (errstr string) {
	//var index int
	ind := strings.IndexByte(uid_ser, '@')
	if ind == -1 {
		errString := "Invalid format of string " + uid_ser
		return errString //, 1
	} else {
		conf := new(VlessServerConfig)
		uid := uid_ser[:ind]
		ser := uid_ser[ind+1:]
		portInd := strings.IndexByte(ser, ':')
		conf.Address = ser[:portInd]
		//check ip
		if !isIpValid(config.IpCheckServer, conf.Address, config.IpCheckKey,
			config.IpCheckValue, config.IpCheckBlackList) {
			return "Ip is invalid"
		}
		//
		i, err := strconv.Atoi(ser[portInd+1:])
		if err != nil {
			errString := "Invalid format of port " + ser
			return errString //, 4
		}
		conf.Port = i
		user := new(VlessUser)
		user.Id = uid
		user.Encryption = "none"
		streamSettings := new(XrStreamSettings)
		if len(params) > 0 {
			paramsMap := createParamsMap(params)
			netType, ok := paramsMap["type"]
			if ok {
				streamSettings.Network = netType
				switch netType {
				case "tcp":
					tcppar := createTcpParam(paramsMap)
					streamSettings.TcpSettings = tcppar
				case "ws":
					wspar := createWsParams(paramsMap)
					streamSettings.WsSettings = wspar
				case "grpc":
					grpspar := createGrpcParams(paramsMap)
					streamSettings.GrpcSettings = grpspar
				case "xhttp":
					//
				}
			}
			sec, ok := paramsMap["security"]
			if ok {
				streamSettings.Security = sec
				switch sec {
				case "tls":
					tlsset := createTlsParams(paramsMap)
					streamSettings.TlsSettings = tlsset
				case "reality":
					realset := createRealityParams(paramsMap)
					streamSettings.RealitySettings = realset
					flow, ok := paramsMap["flow"]
					if ok {
						user.Flow = flow
					}
				}
			}
		}
		conf.Users = append(conf.Users, *user)
		xrconf := new(XrayConf)
		xrconf.Protocol = "vless"
		servers := new(XrVlessServerConfig)
		servers.Vless = append(servers.Vless, *conf)
		xrconf.Settings = servers
		xrconf.StreamSet = *streamSettings
		confToSave++
		xrconf.Tag = config.Tag + strconv.Itoa(confToSave) //config.VlessTag + strconv.Itoa(len(xrVlConfigs)+1)
		xrVlConfigs = append(xrVlConfigs, *xrconf)
		vlessConfToSave = vlessConfToSave + 1
	}
	return ""
}
