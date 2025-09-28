package main

import (
	"bytes"
	//"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"

	//"strconv"
	//"strings"
	"sync"
)

var config Config
var linksCount int

var xrSsConfigs []XrayConf
var xrVlConfigs []XrayConf
var xrVmConfigs []XrayConf
var xrTrConfigs []XrayConf
var parseresult ParseResult

var confToSave int = 0
var ssConfToSave int = 0
var vlessConfToSave int = 0
var vmessConfToSave int = 0
var trojanConfToSave int = 0

type Link struct {
	Url           string
	Mask          []string
	ConfigCount   int
	ParseTopToBot bool
}

type Config struct {
	XrConfigFile      string
	XrPath            string
	XrRestartCommand  []string
	ConfigSectionPath []string
	ServersEditPos    int
	Tag               string
	//SsConfigSectionPath []string
	//SsServersEditPos    int
	//SsModeDefault       string
	//SsTimeOutDefault    int32
	//SsTag string
	//SsMultipleOutbounds    bool
	//VlessConfigSectionPath []string
	//VlessServersEditPos    int
	//VlessMultipleOutbounds bool
	//VlessTag               string
	//VmessConfigSectionPath []string
	//VmessServersEditPos    int
	//VmessTag               string
	OutputFile string
	Links      []Link
}

type ParseResult struct {
	XrSsConfigs     []XrayConf `json:"xrss,omitzero"`
	VlessXrConfigs  []XrayConf `json:"xrvless,omitzero"`
	VmessXrConfigs  []XrayConf `json:"xrvmess,omitzero"`
	TrojanXrConfigs []XrayConf `json:"xrtrojan,omitzero"`
}

type XrayConf struct {
	Protocol  string           `json:"protocol"`
	Settings  any              `json:"settings"` //XrSsServerConf
	StreamSet XrStreamSettings `json:"streamSettings,omitzero"`
	Tag       string           `json:"tag"`
}

type XrStreamSettings struct {
	Network         string            `json:"network,omitempty"`
	Security        string            `json:"security,omitempty"`
	TlsSettings     XrTlsSettings     `json:"tlsSettings,omitzero"`
	RealitySettings XrRealitySettings `json:"realitySettings,omitzero"`
	WsSettings      XrWsSettings      `json:"wsSettings,omitzero"`
	GrpcSettings    XrGrpcSettings    `json:"grpcSettings,omitzero"`
	TcpSettings     XrTcpSettings     `json:"rawSettings,omitzero"`
}

type XrWsSettings struct {
	AcceptProxyProtocol bool        `json:"acceptProxyProtocol,omitempty"`
	Path                string      `json:"path,omitempty"`
	Host                string      `json:"host,omitempty"`
	Headers             XrWsHeaders `json:"headers,omitzero"`
	HBPeriod            int         `json:"heartbeatPeriod,omitempty"`
}

type XrWsHeaders struct {
	Key   string
	Value string
}

type XrGrpcSettings struct {
	Authority           string `json:"authority,omitempty"`
	ServiceName         string `json:"serviceName,omitempty"`
	MultyMode           bool   `json:"multyMode,omitempty"`
	UserAgent           string `json:"user_agent,omitempty"`
	IdleTimeout         int    `json:"idle_timeout,omitempty"`
	HealthCheckTimeOut  int    `json:"health_check_timeout,omitempty"`
	PermitWithoutStream bool   `json:"permit_without_stream,omitempty"`
	InitWinSize         int    `json:"initial_windows_size,omitempty"`
}

type XrTcpSettings struct {
	AcceptProxyProtocol bool        `json:"acceptProxyProtocol,omitempty"`
	Header              XrTcpHeader `json:"header,omitzero"`
}

type XrTcpHeader struct {
	Htype string `json:"type,omitempty"`
}

type XrTlsSettings struct {
	ServerName                       string           `json:"serverName,omitempty"`
	VerifyPeerSertInNames            string           `json:"verifyPeerCertInNames,omitempty"`
	RejectUnknownSni                 bool             `json:"rejectUnknownSni,omitempty"`
	AllowInsecure                    bool             `json:"allowInsecure,omitempty"`
	Alpn                             []string         `json:"alpn,omitempty"`
	MinVersion                       string           `json:"minVersion,omitempty"`
	MaxVersion                       string           `json:"maxVersion,omitempty"`
	ChiperSuites                     string           `json:"cipherSuites,omitempty"`
	Certificates                     []XrCertificates `json:"certificates,omitempty"`
	DisableSystemRoot                bool             `json:"disableSystemRoot,omitempty"`
	EnableSessionResumption          bool             `Json:"enableSessionResumption,omitempty"`
	Fingerprint                      string           `json:"fingerprint,omitempty"`
	PinnedPeerCertificateChainSha256 []string         `json:"pinnedPeerCertificateChainSha256,omitempty"`
	CurvePreferences                 []string         `json:"curvePreferences,omitempty"`
	MasterKeyLog                     string           `json:"masterKeyLog,omitempty"`
	EchConfigList                    string           `json:"echConfigList,omitempty"`
	EchServerKeys                    string           `json:"echServerKeys,omitempty"`
}

type XrCertificates struct {
	OcspStapling    json.Number `json:"ocspStapling,omitempty"`
	OneTimeLoading  bool        `json:"oneTimeLoading,omitempty"`
	Usage           string      `json:"usage,omitempty"`
	BuildChain      bool        `json:"buildChain,omitempty"`
	CertificateFile string      `json:"certificateFile,omitempty"`
	Certificate     []string    `json:"certificate,omitempty"`
	KeyFile         string      `json:"keyFile,omitempty"`
	Key             []string    `json:"key,omitempty"`
}

type XrRealitySettings struct {
	Show                  bool                  `json:"show,omitempty"`
	Target                string                `json:"target,omitempty"`
	Xver                  int                   `json:"xver,omitempty"`
	ServerNames           []string              `json:"serverNames,omitzero"`
	PrivateKey            string                `json:"privateKey,omitempty"`
	MinClientVer          string                `json:"minClientVer,omitempty"`
	MaxClientVer          string                `json:"maxClientVer,omitempty"`
	MAxTimeDiff           int                   `json:"maxTimeDiff,omitempty"`
	ShortIds              []string              `json:"shortIds,omitzero"`
	LimitFallbackUpload   LimitFallbackUpload   `json:"limitFallbackUpload,omitzero"`
	LimitFallbackDownload LimitFallbackDownload `json:"limitFallbackDownload,omitzero"`
	Fingerprint           string                `json:"fingerprint"`
	ServerName            string                `json:"serverName,omitempty"`
	ShortId               string                `json:"shortId,omitempty"`
	Password              string                `json:"password,omitempty"`
	Mldsa65Verify         string                `json:"mldsa65Verify,omitempty"`
	SpiderX               string                `json:"spiderX,omitempty"`
}

type LimitFallbackUpload struct {
	AfterBytes       int `json:"afterBytes,omitempty"`
	BytesPerSec      int `json:"bytesPerSec,omitempty"`
	BurstBytesPerSec int `json:"burstBytesPerSec,omitempty"`
}

type LimitFallbackDownload struct {
	AfterBytes       int `json:"afterBytes,omitempty"`
	BytesPerSec      int `json:"bytesPerSec,omitempty"`
	BurstBytesPerSec int `json:"burstBytesPerSec,omitempty"`
}

func createParamsMap(str string) map[string]string {
	paramsMap := make(map[string]string)
	lenStr := len(str)
	j := 0
	for i := 0; i < lenStr; i++ {
		if str[i] == '&' || i == lenStr-1 {
			if i == lenStr-1 {
				i++
			}
			par := str[j:i]
			k := len(par)
			for n := 0; n < k; n++ {
				if par[n] == '=' {
					name := par[:n]
					val := par[n+1:]
					paramsMap[name] = val
					break
				}
			}
			i = i + 5 // lenght of "&amp;"
			j = i
		}
	}
	return paramsMap
}

func createTlsParams(parMap map[string]string) (tlsset XrTlsSettings) {
	sname, ok := parMap["sni"]
	if ok {
		tlsset.ServerName = sname
	}
	alpn, ok := parMap["alpn"]
	if ok {

		tlsset.Alpn = append(tlsset.Alpn, alpn)
	}
	return tlsset
}

func createRealityParams(parMap map[string]string) (realset XrRealitySettings) {
	sname, ok := parMap["sni"]
	if ok {
		realset.ServerName = sname
	}
	passw, ok := parMap["pbk"]
	if ok {
		realset.Password = passw
	}
	fp, ok := parMap["fp"]
	if ok {
		realset.Fingerprint = fp
	}
	sid, ok := parMap["sid"]
	if ok {
		realset.ShortId = sid
	}
	spx,ok := parMap["spx"]
	if ok {
		if spx == "%2F" {
			spx = "/"
		}
		realset.SpiderX = spx
	}
	return realset
}

func createWsParams(parMap map[string]string) (wsset XrWsSettings) {
	host, ok := parMap["host"]
	if ok {
		wsset.Host = host
	}
	path, ok := parMap["path"]
	if ok {
		if path == "%2F" {
			path = "/"
		}
		wsset.Path = path
	}
	return wsset
}

func createGrpcParams(parMap map[string]string) (grpcPar XrGrpcSettings) {
	sname, ok := parMap["sn"]
	if ok {
		grpcPar.ServiceName = sname
	}
	return grpcPar
}

func createTcpParam(parMap map[string]string) (tcpPar XrTcpSettings) {
	htype, ok := parMap["headerType"]
	if ok {
		tcpPar.Header.Htype = htype
	} else {
		tcpPar.Header.Htype = "none"
	}
	return tcpPar
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return !errors.Is(err, os.ErrNotExist)
}

func readConfig(path string) {
	file, err := os.Open(path)
	if err != nil { // если возникла ошибка
		fmt.Println("Unable to create file:", err)
		os.Exit(1) // выходим из программы
	}
	defer file.Close()
	data, err := os.ReadFile(path)
	if err != nil {
		fmt.Println("Unable to read file:", err)
		os.Exit(1)
	}
	jsonErr := json.Unmarshal(data, &config)
	if jsonErr != nil {
		fmt.Println("Unable to parse json:", jsonErr)
		os.Exit(1)
	}

}

func parseUp(link Link, body string) {
	lastPos := len(body)
	count := link.ConfigCount
	maskLen := len(link.Mask)
	i := lastPos - 10
	for i >= 0 {
		for j := 0; j < maskLen; j++ {
			mask := link.Mask[0]
			if body[i] == mask[0] {
				lm := len(mask)
				_mask := body[i : i+lm]
				if mask == _mask {
					c := i + lm
					for c <= lastPos {
						if body[c] == '#' || body[c] == ' ' || body[c] == '<' || body[c] == '\\' { //
							str := body[i+lm : c]
							if mask == "ss://" {
								decodeSsServerConfig(str)
								break
							}
							if mask == "vless://" {
								decodeVlessServerConfig(str)
								break
							}
							if mask == "vmess://" {
								decodeVmessServerConfig(str)
								break
							}
							if mask == "trojan://" {
								decodeTrojanServerConfig(str)
								break
							}
						}
						c++
					}
					count = count - 1
					i = i - 10
					lastPos = i
				}
			}
		}
		if count == 0 {
			break
		}
		i = i - 1
	}
}

func parseDown(link Link, body string) {
	lastPos := len(body)
	count := link.ConfigCount
	maskLen := len(link.Mask)
	for i := 0; i < lastPos; i++ {
		for j := 0; j < maskLen; j++ {
			mask := link.Mask[0]
			if body[i] == mask[0] {
				lm := len(mask)
				_mask := body[i : i+lm]
				if mask == _mask {
					c := i + lm
					for c <= lastPos {
						if body[c] == '#' || body[c] == ' ' || body[c] == '<' || body[c] == '\\' { //
							str := body[i+lm : c]
							if mask == "ss://" {
								decodeSsServerConfig(str)
								break
							}
							if mask == "vless://" {
								decodeVlessServerConfig(str)
								break
							}
							if mask == "vmess://" {
								decodeVmessServerConfig(str)
								break
							}
							if mask == "trojan://" {
								decodeTrojanServerConfig(str)
								break
							}
						}
						c++
					}
					count = count - 1
					i = c
				}
			}
		}
		if count == 0 {
			break
		}
	}
}

func parse(link Link, body string) {
	if link.ParseTopToBot {
		parseDown(link, body)
	} else {
		parseUp(link, body)
	}
}

func getHtml(link Link, wg *sync.WaitGroup) {
	defer wg.Done()
	response, err := http.Get(link.Url)
	if err != nil {
		fmt.Println("Unable to connect to server:", err)
	} else if response.StatusCode == 200 {
		defer response.Body.Close()
		body, err := io.ReadAll(response.Body)
		if err != nil {
			fmt.Println("Unable to read html body:", err)
		} else {
			parse(link, string(body))
		}
	} else {
		fmt.Println("Unable to get html:", err)
	}
}

func saveParseResult(resFile os.File) bool {
	parseresult.XrSsConfigs = xrSsConfigs
	parseresult.VlessXrConfigs = xrVlConfigs
	parseresult.VmessXrConfigs = xrVmConfigs
	parseresult.TrojanXrConfigs = xrTrConfigs
	jsondata, err := json.MarshalIndent(parseresult, "", "	") //ssConfigs
	if err != nil {
		fmt.Println("json encoding conf error", err)
		return false
	} else {
		_, err := resFile.Write(jsondata)
		if err != nil {
			fmt.Println("json writning conf err", err)
			return false
		} else {
			return true
		}
	}
}

func main() {
	restart := false
	args := os.Args
	args_count := len(args)
	if args_count > 1 {
		if args[1] == "help" {
			fmt.Println("help not ready")
			os.Exit(1)
		} else if args[1] == "version" {
			fmt.Println("version 1.0")
			os.Exit(1)
		} else {
			path := args[1]
			if fileExists(path) {
				readConfig(path)
				//fmt.Println(config)
			} else {
				fmt.Println("config file not exists")
				os.Exit(1)
			}
		}
	}
	linksCount = len(config.Links)
	if linksCount == 0 {
		fmt.Println("Links for parsing is not defined")
		os.Exit(1)
	}
	var waitgroup sync.WaitGroup
	resultFile, err := os.Create(config.OutputFile)
	if err != nil { // если возникла ошибка
		fmt.Println("Unable to create file:", err)
	}
	defer resultFile.Close()
	for i := 0; i < linksCount; i++ {
		waitgroup.Add(1)
		go getHtml(config.Links[i], &waitgroup)
	}
	waitgroup.Wait()
	saveRes := saveParseResult(*resultFile)
	// --------
	if saveRes {
		rawConf, err := os.ReadFile(config.OutputFile) //
		if err != nil {
			fmt.Println("Unable to read parsingresult file:", err)
		} else {
			var middle []byte
			if ssConfToSave > 0 {
				section := ReadSection("xrss", rawConf)
				middle = bytes.Join([][]byte{middle, section}, nil)
			}
			if vlessConfToSave > 0 {
				section := ReadSection("xrvless", rawConf)
				if len(middle) > 0 {
					middle = append(middle, ',')
				}
				middle = bytes.Join([][]byte{middle, section}, nil)
			}
			if vmessConfToSave > 0 {
				section := ReadSection("xrvmess", rawConf)
				if len(middle) > 0 {
					middle = append(middle, ',')
				}
				middle = bytes.Join([][]byte{middle, section}, nil)
			}
			if trojanConfToSave > 0 {
				section := ReadSection("xrtrojan", rawConf)
				if len(middle) > 0 {
					middle = append(middle, ',')
				}
				middle = bytes.Join([][]byte{middle, section}, nil)
			}
			if len(middle) > 0 && setConfigs(config.XrConfigFile, middle, config.ServersEditPos) {
				restart = true
			}
		}
	}
	// --------
	/*if ssConfToSave > 0 {
		if saveRes {
			rawSsConf, err := os.ReadFile(config.OutputFile) //
			if err != nil {
				fmt.Println("Unable to read parsingresult file:", err)
			}
			middle := ReadSection("xrss", rawSsConf) // rawSsConf[1 : len(rawSsConf)-1]
			if middle != nil && setSsServiceConfig(config.XrConfigFile, middle) {
				restart = true
			} else {
				ssConfToSave = 0
			}
		}
	}
	if vlessConfToSave > 0 {
		if saveRes {
			rawVlConf, err := os.ReadFile(config.OutputFile) //
			if err != nil {
				fmt.Println("Unable to read parsingresult file:", err)
			}
			middle := ReadSection("xrvless", rawVlConf) // rawSsConf[1 : len(rawSsConf)-1]
			if middle != nil && setVlServiceConfig(config.XrConfigFile, middle) {
				restart = true
			} else {
				vlessConfToSave = 0
			}
		}
	}
	if vmessConfToSave > 0 {

	}*/
	if restart {
		restartService()
	}
	fmt.Println("parser finish")
}

func restartService() {
	xrbin, lookerr := exec.LookPath(config.XrPath)
	if lookerr != nil {
		fmt.Println("Unable to find xray bin:", lookerr)
	} else { // restart ss
		//env := os.Environ()
		cmd := exec.Command(xrbin, config.XrRestartCommand...)
		cmd.Stdout = os.Stdout
		err := cmd.Start() //syscall.Exec(ssbin,config.SsRestartCommand,env)
		if err != nil {
			fmt.Println("Unable to restart xray:", err)
		}
	}
}

func setConfigs(path string, middle []byte, editpos int) bool {
	if fileExists(path) {
		file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, os.ModePerm)
		if err != nil { // если возникла ошибка
			fmt.Println("Unable to open file:", err)
			return false
		}
		defer file.Close()
		data, err := os.ReadFile(path)
		if err != nil {
			fmt.Println("Unable to read xray config file:", err)
			return false
		}
		secPos := findSection(data, config.ConfigSectionPath)
		res, startPosToEdit, endPosToEdit := findPosToEdit(data, secPos, editpos)
		if res {
			first := data[:startPosToEdit+1]
			if editpos > 0 {
				first = append(first, ',')
			}
			last := data[endPosToEdit:]
			newdata := bytes.Join([][]byte{first, middle, last}, nil) //make([]byte, 0, len(first)+len(ssConfigs)+len(last))

			_, writeerr := file.Write(newdata) //os.WriteFile(path, newdata, perm)
			if writeerr != nil {
				fmt.Println("Unable to write config file:", writeerr)
				return false
			}
			truncerr := file.Truncate(int64(len(newdata)))
			if truncerr != nil {
				fmt.Println("Unable to set size of config file:", truncerr)
				return false
			}
		}
	} else {
		return false
	}
	return true
}

/*func setSsServiceConfig(path string, middle []byte) bool {
	if fileExists(path) {
		file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, os.ModePerm)
		if err != nil { // если возникла ошибка
			fmt.Println("Unable to open file:", err)
			return false
		}
		defer file.Close()
		data, err := os.ReadFile(path)
		//fileInfo, err := os.Stat(path)
		//perm := fileInfo.Mode().Perm()
		if err != nil {
			fmt.Println("Unable to read SS config file:", err)
			return false
		}
		secPos := findSection(data, config.SsConfigSectionPath)
		editpos := config.SsServersEditPos + config.VlessServersEditPos
		res, startPosToEdit, endPosToEdit := findPosToEdit(data, secPos, editpos)
		if res {
			first := data[:startPosToEdit+1]
			if editpos > 0 {
				first = append(first, ',')
			}
			last := data[endPosToEdit:]
			newdata := bytes.Join([][]byte{first, middle, last}, nil) //make([]byte, 0, len(first)+len(ssConfigs)+len(last))
			_, writeerr := file.Write(newdata)                        //os.WriteFile(path, newdata, perm)
			if writeerr != nil {
				fmt.Println("Unable to write ss config file:", writeerr)
				return false
			}
			truncerr := file.Truncate(int64(len(newdata)))
			if truncerr != nil {
				fmt.Println("Unable to write ss config file:", truncerr)
				return false
			}
		}
	} else {
		return false
	}
	return true
}

func setVlServiceConfig(path string, middle []byte) bool {
	if fileExists(path) {
		file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, os.ModePerm)
		if err != nil { // если возникла ошибка
			fmt.Println("Unable to open file:", err)
			return false
		}
		defer file.Close()
		data, err := os.ReadFile(path)
		//fileInfo, err := os.Stat(path)
		//perm := fileInfo.Mode().Perm()
		if err != nil {
			fmt.Println("Unable to read SS config file:", err)
			return false
		}
		secPos := findSection(data, config.VlessConfigSectionPath)
		editpos := config.SsServersEditPos + config.VlessServersEditPos + ssConfToSave
		res, startPosToEdit, endPosToEdit := findPosToEdit(data, secPos, editpos)
		if res {
			first := data[:startPosToEdit+1]
			if editpos > 0 {
				first = append(first, ',')
			}
			last := data[endPosToEdit:]
			newdata := bytes.Join([][]byte{first, middle, last}, nil) //make([]byte, 0, len(first)+len(ssConfigs)+len(last))
			_, writeerr := file.Write(newdata)                        //os.WriteFile(path, newdata, perm)
			if writeerr != nil {
				fmt.Println("Unable to write ss config file:", writeerr)
				return false
			}
			truncerr := file.Truncate(int64(len(newdata)))
			if truncerr != nil {
				fmt.Println("Unable to write ss config file:", truncerr)
				return false
			}
		}
	} else {
		return false
	}
	return true
}*/

func ReadSection(name string, data []byte) (res []byte) {
	datalen := len(data)
	namelen := len(name)
	for i := 0; i < datalen; i++ {
		if data[i] == name[0] {
			_name := string(data[i : i+namelen])
			if _name == name {
				for j := i + namelen; j < datalen; j++ {
					if data[j] == '[' {
						endpos := findTokenEnd(data, j+1, datalen, '[', ']')
						if endpos > 0 {
							res = data[j+1 : endpos]
							return res
						} else {
							return nil
						}
					}
				}
			}
		}
	}
	return nil
}

func findNextSection(data []byte, section string, pos int, datalen int) (nextpos int) {
	res := -1
	seclen := len(section)
	for i := pos; i < datalen; i++ {
		if data[i] == section[0] {
			name := string(data[i : i+seclen])
			if name == section { // section found
				res = i + seclen
				return res
			}
		}
	}
	return res
}

func findSection(data []byte, sectionPart []string) (startPos int) {
	res := -1
	datalen := len(data)
	pos := 0
	for s := 0; s < len(sectionPart); s++ {
		section := sectionPart[s]
		pos = findNextSection(data, section, pos, datalen)
		if pos < 0 {
			return pos
		}
	}
	if pos > 0 {
		res = pos
	}
	return res
}

func findPosToEdit(data []byte, startpos int, editpos int) (res bool, start int, end int) {
	res = false
	datalen := len(data)
	count := 0
	for i := startpos; i < datalen; i++ {
		if data[i] == '[' {
			end = findTokenEnd(data, i+1, datalen, '[', ']')
			if end > 0 {
				if editpos == 0 { //config.SsServersEditPos
					start = i
					res = true
					return res, start, end
				}
				for j := i; j < end; j++ {
					if data[j] == '{' { //
						count++
						c := findTokenEnd(data, j+1, end, '{', '}')
						if editpos == count { //config.SsServersEditPos
							start = c
							res = true
							return res, start, end
						} else {
							j = c
						}
					}
				}
			}
		}
	}
	return res, 0, 0
}

func findTokenEnd(data []byte, startpos int, end int, token byte, closeToken byte) (endpos int) {
	count := 0
	for i := startpos; i < end; i++ {
		switch data[i] {
		case token:
			{
				count++
			}
		case closeToken:
			{
				if count == 0 {
					return i
				} else {
					count--
				}
			}
		}
	}
	return 0 // error - token not found
}
