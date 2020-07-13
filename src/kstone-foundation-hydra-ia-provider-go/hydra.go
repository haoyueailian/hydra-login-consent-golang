package main

import (
	// "bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
	"time"
)

var hydraUrl string = "http://localhost:9002"

func Get(flow, challenge string) (map[string]interface{}, error) {
	var resGet map[string]interface{}
	client := &http.Client{
		Timeout: time.Second * 10,
	}
	url := hydraUrl + "/oauth2/auth/requests/" + flow + "/" + challenge

	request, err := http.NewRequest("GET", url, nil)

	if err != nil {
		fmt.Println(err)
		return map[string]interface{}{}, err
	}
	response, _ := client.Do(request)

	status := response.StatusCode
	if status < 200 || status > 302 {
		//
		body, _ := ioutil.ReadAll(response.Body)
		if err != nil {
			log.Fatal(err)
			return map[string]interface{}{}, err
		}
		fmt.Println(string(body))
	}
	defer response.Body.Close()
	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		// handle error
		fmt.Println(err)
		return map[string]interface{}{}, err
	}
	body_error := json.Unmarshal(body, &resGet)

	return resGet, body_error
}

func Put(flow, action, challenge string, body map[string]interface{}) (map[string]interface{}, error) {
	var resPut map[string]interface{}
	client := &http.Client{
		Timeout: time.Second * 10,
	}
	url := hydraUrl + "/oauth2/auth/requests/" + flow + "/" + challenge + "/" + action

	body_content, _ := json.Marshal(body)

	content := string(body_content)
	request, err := http.NewRequest("PUT", url, strings.NewReader(content))

	if err != nil {
		fmt.Println(err)
		return map[string]interface{}{}, err
	}
	request.Header.Set("Content-type", "application/x-www-form-urlencoded")
	response, _ := client.Do(request)

	//
	if response.StatusCode < 200 || response.StatusCode > 302 {
		body, _ := ioutil.ReadAll(response.Body)

		body_error := json.Unmarshal(body, &resPut)
	
		return map[string]interface{}{}, body_error
	}
	defer response.Body.Close()
	bodyP, err := ioutil.ReadAll(response.Body)
	if err != nil {
		fmt.Println(err)
		return map[string]interface{}{}, err
	}

	body_error := json.Unmarshal(bodyP, &resPut)
	fmt.Println(body_error)
	return resPut, body_error
}

func GetLoginRequest(challenge string) (map[string]interface{}, error) {
	return Get("login", challenge)
}

func AcceptLoginRequest(challenge string, body map[string]interface{}) (map[string]interface{}, error) {
	return Put("login", "accept", challenge, body)
}

func RejectLoginRequest(challenge string, body map[string]interface{}) (map[string]interface{}, error) {
	return Put("login", "reject", challenge, body)
}

func GetConsentRequest(challenge string) (map[string]interface{}, error) {
	return Get("consent", challenge)
}

func AcceptConsentRequest(challenge string, body map[string]interface{}) (map[string]interface{}, error) {
	return Put("consent", "accept", challenge, body)
}

func RejectConsentRequest(challenge string, body map[string]interface{}) (map[string]interface{}, error) {
	return Put("consent", "reject", challenge, body)
}
