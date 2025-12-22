package main

import (
	"fmt"
	"strconv"
	"strings"
)

type XrTrojanServerConfig struct {
	Trojan []TrojanServerConfig `json:"servers"`
}

type TrojanServerConfig struct {
	Address  string `json:"address"`
	Port     int    `json:"port"`
	Password string `json:"password"`
}

func decodeTrojanServerConfig(str string) bool {
	var ser_passw string
	var params string
	index := strings.IndexByte(str, '?')
	if index == -1 { // no params
		index = strings.IndexByte(str, '@')
		if index == -1 {
			fmt.Println("Can not decode config")
			return false
		} else {
			ser_passw = str
			params = ""
		}
	} else {
		ser_passw = str[:index]
		params = str[index+1:]
	}
	errstr := createTrojanServerConfig(ser_passw, params)
	if errstr != "" {
		fmt.Println(errstr)
		return false
	}
	return true
}

func createTrojanServerConfig(ser_passw string, params string) (errstr string) {
	ind := strings.IndexByte(ser_passw, '@')
	if ind == -1 {
		errString := "Invalid format of string " + ser_passw
		return errString //, 1
	} else {
		conf := new(TrojanServerConfig)
		passw := ser_passw[:ind]
		conf.Password = passw
		ser := ser_passw[ind+1:]
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
				}
			}
		}
		xrconf := new(XrayConf)
		xrconf.Protocol = "trojan"
		servers := new(XrTrojanServerConfig)
		servers.Trojan = append(servers.Trojan, *conf)
		xrconf.Settings = servers
		xrconf.StreamSet = *streamSettings
		confToSave++
		xrconf.Tag = config.Tag + strconv.Itoa(confToSave) //
		xrTrConfigs = append(xrTrConfigs, *xrconf)
		trojanConfToSave = trojanConfToSave + 1
	}
	return ""
}
