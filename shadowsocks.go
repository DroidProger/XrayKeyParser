package main

import (
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
)

type XrSsServers struct {
	SsServers []SsServerConf `json:"servers"`
}

type SsServerConf struct {
	Address  string `json:"address"`
	Port     int    `json:"port"`
	Method   string `json:"method"`
	Password string `json:"password"`
	UoT      bool   `json:"uot,omitempty"`
}

func decodeSsServerConfig(str string) bool {
	var datastr string
	index := strings.IndexByte(str, '@')
	if index == -1 { // fully encoded string
		data, err := base64.StdEncoding.DecodeString(str)
		if err != nil {
			fmt.Println("error:", err)
			return false
		}
		datastr = string(data[:])
	} else { // encoded only method:password
		shortstr := str[:index]
		data, err := base64.StdEncoding.DecodeString(shortstr)
		if err != nil {
			fmt.Println("error:", err)
			return false
		}
		datastr = string(data[:]) + str[index:]
	}
	errstr := createSsServerConfig(datastr)
	if errstr != "" {
		fmt.Println(errstr)
		return false
	}
	return true
}

func createSsServerConfig(str string) (errstr string) {
	var index int
	ind := strings.IndexByte(str, '@')
	if ind == -1 {
		errString := "Invalid format of string " + str
		return errString //, 1
	} else {
		mpstr := str[:ind]
		conf := new(SsServerConf)
		index = strings.IndexByte(mpstr, ':')
		if index == -1 {
			errString := "Invalid format of string " + mpstr
			return errString //, 2
		} else {
			conf.Method = mpstr[:index]
			conf.Password = mpstr[index+1:]
		}
		spstr := str[ind+1:]
		// find '?'
		indx := strings.IndexByte(spstr, '/')
		if indx != -1 {
			spstr = spstr[:indx]
		} else {
			indx := strings.IndexByte(spstr, '?')
			if indx != -1 {
				spstr = spstr[:indx]
			}
		}
		index = strings.IndexByte(spstr, ':')
		if index == -1 {
			errString := "Invalid format of string " + spstr
			return errString //, 3
		} else {
			conf.Address = spstr[:index]
			//check ip
			if !isIpValid(config.IpCheckServer, conf.Address, config.IpCheckKey, config.IpCheckValue) {
				return "Ip is invalid"
			}
			//
			i, err := strconv.Atoi(spstr[index+1:])
			if err != nil {
				errString := "Invalid format of port " + spstr
				return errString //, 4
			}
			conf.Port = i
		}
		xrconf := new(XrayConf)
		xrconf.Protocol = "shadowsocks"
		servers := new(XrSsServers)
		servers.SsServers = append(servers.SsServers, *conf)
		xrconf.Settings = servers
		confToSave++
		xrconf.Tag = config.Tag + strconv.Itoa(confToSave) //config.SsTag + strconv.Itoa(len(xrSsConfigs)+1)
		xrSsConfigs = append(xrSsConfigs, *xrconf)
		ssConfToSave = ssConfToSave + 1
	}
	return "" //, 0
}
