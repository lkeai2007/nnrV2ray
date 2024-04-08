package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// APIResponse represents the structure of the common API response
type APIResponse struct {
	Status int         `json:"status"`
	Data   interface{} `json:"data"`
}

const (
	UUID      = "xxxxx"
	XUIIP     = "xxxxxxxxx"
	typevless = "ws"
	XuiPort   = 12345
	NNRtoken     = "xxxxxxx"
	urlport   = ":80"
	password  = "xxxxxxxxxx"
	// Define a constant to control whether to use a proxy or not
	useProxy = false
)
//
const (
	urlex = "https://nnr.moe"
	proxyStr = "http://localhost:10809" // Replace with your local proxy address
)

// Rule represents the structure of a rule
type Rule struct {
	RID     string                 `json:"rid"`
	SID     string                 `json:"sid"`
	Host    string                 `json:"host"`
	Port    int                    `json:"port"`
	Remote  string                 `json:"remote"`
	RPort   int                    `json:"rport"`
	Type    string                 `json:"type"`
	Name    string                 `json:"name"`
	Traffic int64                  `json:"traffic"`
	Setting map[string]interface{} `json:"setting"`
}

// Node represents the structure of a node
type Node struct {
	SID    string   `json:"sid"`
	Name   string   `json:"name"`
	Host   string   `json:"host"`
	Min    int      `json:"min"`
	Max    int      `json:"max"`
	MF     float64  `json:"mf"`
	Level  int      `json:"level"`
	Detail string   `json:"detail"`
	Types  []string `json:"types"`
}
type nnrStruct struct {
	Name string
	Host []string
	Port int
}

// MakeAPICall makes a POST API call with the given URL, payload, and token
func MakeAPICall(urlhou, token string, payload []byte) (*APIResponse, error) {
	req, err := http.NewRequest("POST", urlex+urlhou, bytes.NewBuffer(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Token", token)

	

	var client *http.Client
	if useProxy {
		// Configure proxy URL
		
		proxyURL, err := url.Parse(proxyStr)
		if err != nil {
			log.Fatal("Error parsing proxy URL: ", err)
		}

		// Set up the HTTP client with the proxy
		transport := &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		}
		client = &http.Client{
			Transport: transport,
		}
	} else {
		// Use the default HTTP client without a proxy
		client = http.DefaultClient
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	// fmt.Println(string(body))
	apiResponse := &APIResponse{}
	err = json.Unmarshal(body, apiResponse)
	if err != nil {
		return nil, err
	}

	return apiResponse, nil
}


// GetRuleByID retrieves a rule by its ID
func GetRuleByID(rid, token string) (*Rule, error) {
	apiURL := fmt.Sprintf("/api/rules/get?rid=%s", rid)
	apiResponse, err := MakeAPICall(apiURL, token, nil)
	if err != nil {
		return nil, err
	}

	if apiResponse.Status == 1 {
		ruleData, ok := apiResponse.Data.(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("Error parsing rule data")
		}

		ruleBytes, err := json.Marshal(ruleData)
		if err != nil {
			return nil, err
		}

		rule := &Rule{}
		err = json.Unmarshal(ruleBytes, rule)
		if err != nil {
			return nil, err
		}

		return rule, nil
	}

	return nil, fmt.Errorf("Failed to get rule: %v", apiResponse.Data)
}

// GetAllRules retrieves all rules
func GetAllRules(token string) ([]Rule, error) {
	apiURL := "/api/rules/"
	apiResponse, err := MakeAPICall(apiURL, token, nil)
	if err != nil {
		return nil, err
	}

	if apiResponse.Status == 1 {
		rulesData, ok := apiResponse.Data.([]interface{})
		if !ok {
			return nil, fmt.Errorf("Error parsing rules data")
		}

		rulesBytes, err := json.Marshal(rulesData)
		if err != nil {
			return nil, err
		}

		var rules []Rule
		err = json.Unmarshal(rulesBytes, &rules)
		if err != nil {
			return nil, err
		}

		return rules, nil
	}

	return nil, fmt.Errorf("Failed to get all rules: %v", apiResponse.Data)
}

// GetAllNodes retrieves all nodes
func GetAllNodes(token string) ([]Node, error) {
	apiURL := "/api/servers"
	apiResponse, err := MakeAPICall(apiURL, token, nil)
	if err != nil {
		return nil, err
	}

	if apiResponse.Status == 1 {
		nodesData, ok := apiResponse.Data.([]interface{})
		if !ok {
			return nil, fmt.Errorf("Error parsing nodes data")
		}

		nodesBytes, err := json.Marshal(nodesData)
		if err != nil {
			return nil, err
		}

		var nodes []Node
		err = json.Unmarshal(nodesBytes, &nodes)
		if err != nil {
			return nil, err
		}

		return nodes, nil
	}

	return nil, fmt.Errorf("Failed to get all nodes: %v", apiResponse.Data)
}

// AddRule adds a new rule
// Parameters:
//
//	sid - sid
//	port - 源端口
func AddRule(sid string, remote string, rport int, ruleType string, name string, token string) (*Rule, error) {
	payload := map[string]interface{}{
		"sid":    sid,
		"remote": remote,
		"rport":  rport,
		"type":   ruleType,
		"name":   name,
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	apiURL := "/api/rules/add"
	apiResponse, err := MakeAPICall(apiURL, token, payloadBytes)
	if err != nil {
		return nil, err
	}

	if apiResponse.Status == 1 {
		ruleData, ok := apiResponse.Data.(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("Error parsing rule data")
		}

		ruleBytes, err := json.Marshal(ruleData)
		if err != nil {
			return nil, err
		}

		rule := &Rule{}
		err = json.Unmarshal(ruleBytes, rule)
		if err != nil {
			return nil, err
		}

		return rule, nil
	}

	return nil, fmt.Errorf("Failed to add rule: %v", apiResponse.Data)
}

// DeleteRule deletes a rule by its ID
func DeleteRule(rid, token string) error {
	payload := map[string]string{
		"rid": rid,
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	apiURL := "/api/rules/del"
	apiResponse, err := MakeAPICall(apiURL, token, payloadBytes)
	if err != nil {
		return err
	}

	if apiResponse.Status != 1 {
		return fmt.Errorf("Failed to delete rule: %v", apiResponse.Data)
	}

	return nil
}

var (
	vlesss []string
	allRules []Rule
)

func refreshRules() {
	for {
		var err error
		allRules, err = GetAllRules(NNRtoken)
		if err != nil {
			fmt.Println("Error getting all rules: ", err)
		} else {
			if allRules != nil {
				ProductVless(allRules)
			}
		}
		fmt.Println("Rules refreshed at:", time.Now())
		time.Sleep(12 * time.Hour)
	}
}

func ProductVless(rules interface{}) {
	vlesss = make([]string, 0) // 清空vlesss切片,保证是最新的值
	switch v := rules.(type) {
	case *Rule:
		for _, value := range strings.Split(v.Host, ",") {
			vlesss = append(vlesss, fmt.Sprintf("vless://%s@%s:%s?type=ws&security=none&path=%%2F#%s", UUID, value, strconv.Itoa(v.Port), v.Name))
			break
		}
	case []Rule:
		for _, rule := range v {
			for _, value := range strings.Split(rule.Host, ",") {
				vlesss = append(vlesss, fmt.Sprintf("vless://%s@%s:%s?type=ws&security=none&path=%%2F#%s", UUID, value, strconv.Itoa(rule.Port), rule.Name))
				break
			}
		}
	default:
		// 处理不支持的类型
		fmt.Println("Unsupported type")
	}
}

func randomInt(min int, max int) string {
	rand.Seed(time.Now().UnixNano())
	randomNumber := min + rand.Intn(max-min+1)

	return strconv.Itoa(randomNumber)
}

func createAllRule(allNodes []Node) {
	// Add a new rule
	for _, v := range allNodes {
		for index, _ := range strings.Split(v.Host, ",") {
			newRule, err := AddRule(v.SID, XUIIP, XuiPort, "tcp", v.Name+" "+strconv.Itoa(index), NNRtoken)
			if err != nil {
				fmt.Println("Error adding new rule: ", err)
			}
			fmt.Println("Newly added rule:", newRule)
			if newRule != nil {
				ProductVless(newRule)
			}
			break
		}
	}
}
func main() {

	// Example usage of the functions
	// ruleID := "0e316278647a32b5f582146996ab0be5"
	// rule, err := GetRuleByID(ruleID, token)
	// if err != nil {
	// 	log.Fatal("Error getting rule by ID: ", err)
	// }
	// fmt.Println("Rule by ID:", rule)

	// fmt.Println("All rules:", allRules)

	// allNodes, err := GetAllNodes(token)
	// if err != nil {
	// 	log.Fatal("Error getting all nodes: ", err)
	// }
	// fmt.Println("All nodes:", allNodes)

	// for _,v := range vlesss {
	//     fmt.Println(v)
	// }

	// Delete a rule
	// for _,v := range allRules {
	//     err = DeleteRule(v.RID, token)
	//     if err != nil {
	//         log.Fatal("Error deleting rule: ", err)
	//     }
	//     fmt.Println("Rule deleted successfully")
	// }

	go refreshRules()
	// 创建 HTTP 服务器
	http.HandleFunc("/api/vless", func(w http.ResponseWriter, r *http.Request) {
		// 检查密码
		if r.URL.Query().Get("pd") != password {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		var temp string
		// 对 vlesss 的每个值进行 Base64 编码并写入响应
		for _, v := range vlesss {
			temp  += v + "\n"
		}
		encodedValue := base64.StdEncoding.EncodeToString([]byte(temp))
		fmt.Fprintln(w, encodedValue)
	})

	fmt.Printf("Server is running on http://0.0.0.0%s\n", urlport)
	log.Fatal(http.ListenAndServe(urlport, nil))
}
