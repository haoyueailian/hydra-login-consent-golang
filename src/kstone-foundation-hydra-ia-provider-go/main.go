package main

import (
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/julienschmidt/httprouter"
	"github.com/unrolled/render"
	// "github.com/gorilla/csrf"
	// "errors"
	"log"
	"net/http"
	// "strings"
	"io/ioutil"
	// "encoding/json"
	"strconv"
	// "reflect"
	"encoding/json"
	"strings"
	"time"
)

var IAM_URL string = "http://192.169.2.19:35434/iam/actions/login"
var User_id, User_role interface{}

type Render struct {
	*render.Render
}

func (r *Render) Index(w http.ResponseWriter, req *http.Request, _ httprouter.Params) {
	req.ParseForm()
	fmt.Fprint(w, "Welcome!\n")
}

// func (r *Render) Hello(w http.ResponseWriter, req *http.Request, ps httprouter.Params) {
// 	fmt.Fprintf(w, "hello, %s!\n", ps.ByName("name"))
// }

func (r *Render) Login(w http.ResponseWriter, req *http.Request, _ httprouter.Params) {
	challenge := req.URL.Query().Get("login_challenge")
	response, response_err := GetLoginRequest(challenge)

	if response_err != nil {
		r.HTML(w, http.StatusOK, "error", map[string]interface{}{"response_err": response_err})
		return
	}

	skip := response["skip"]
	body := response["subject"] //"subject": username

	if skip.(bool) {
		resp, resp_err := AcceptLoginRequest(challenge, map[string]interface{}{"subject": body})
		if resp_err != nil {
			r.HTML(w, http.StatusOK, "error", map[string]interface{}{"response_err": resp_err})
			return
		}

		redirect_url := resp["redirect_to"]
		http.Redirect(w, req, redirect_url.(string), http.StatusFound)
	}

	r.HTML(w, http.StatusOK, "login", map[string]interface{}{"challenge": challenge, "skip": skip})
}

func (r *Render) HandleLogin(w http.ResponseWriter, req *http.Request, _ httprouter.Params) {
	var resToken map[string]interface{}
	req.ParseForm()
	challenge := req.Form.Get("challenge")

	if challenge == "/" {
		r.HTML(w, http.StatusOK, "error", map[string]interface{}{"challenge": challenge, "error": "challenge 为空"})
		return
	}

	remember := req.Form.Get("remember")
	username := req.Form.Get("username")
	password := req.Form.Get("password")
	remember_bool, _ := strconv.ParseBool(remember)

	if req.Method == "POST" {
		if len(req.Form["username"][0]) == 0 {
			//用户名为空的处理
			fmt.Println("用户名为空")
			r.HTML(w, http.StatusOK, "login", map[string]interface{}{"error": "用户名为空", "challenge": challenge})
			return
		}
		if len(req.Form["password"][0]) == 0 {
			//密码为空的处理
			fmt.Println("密码为空")
			r.HTML(w, http.StatusOK, "login", map[string]interface{}{"error": "密码为空", "challenge": challenge})
			return
		}
		// IAM验证用户
		client := &http.Client{
			Timeout: time.Second * 10,
		}
		body := map[string]interface{}{"username": username, "password": password}
		body_content, _ := json.Marshal(body)
		content := string(body_content)
		request, err := http.NewRequest("POST", IAM_URL, strings.NewReader(content))

		if err != nil {
			fmt.Println(err)
			r.HTML(w, http.StatusOK, "error", map[string]interface{}{"response_err": err})
		}
		request.Header.Set("Content-type", "application/x-www-form-urlencoded")
		response_iam, _ := client.Do(request)
		status := response_iam.StatusCode

		if status != 200 {
			r.HTML(w, http.StatusOK, "login", map[string]interface{}{"error": "用户名或密码错误", "challenge": challenge})
			return
		}
		defer response_iam.Body.Close()
		body_iam, err := ioutil.ReadAll(response_iam.Body)
		if err != nil {
			// handle error
			fmt.Println(err)
			r.HTML(w, http.StatusOK, "error", map[string]interface{}{"read_error": err})
		}
		body_error := json.Unmarshal(body_iam, &resToken)
		fmt.Println(body_error)

		token := resToken["token"]
		// tokenString := "<YOUR TOKEN STRING>"
		claims := jwt.MapClaims{}
		token_decode, err := jwt.ParseWithClaims(token.(string), claims, func(token *jwt.Token) (interface{}, error) {
			return []byte("<YOUR VERIFICATION KEY>"), nil
		})
		// ... error handling
		// do something with decoded claims
		// for key, val := range claims {
		// 		fmt.Printf("Key: %v, value: %v\n", key, val)
		// }

		User_id = claims["id"]
		User_role = claims["user_type"]

		response, response_err := AcceptLoginRequest(challenge, map[string]interface{}{
			"subject":      username,
			"remember":     remember_bool,
			"remember_for": 3600,
		})
		if response_err != nil {
			r.HTML(w, http.StatusOK, "error", map[string]interface{}{"response_err": response_err})
			return
		}

		redirect_to := response["redirect_to"]
		http.Redirect(w, req, redirect_to.(string), http.StatusFound)
	}
}

func (r *Render) Consent(w http.ResponseWriter, req *http.Request, _ httprouter.Params) {
	challenge := req.URL.Query().Get("consent_challenge")
	response, response_err := GetConsentRequest(challenge)
	if response_err != nil {
		r.HTML(w, http.StatusOK, "error", map[string]interface{}{"response_err": response_err})
		return
	}

	subject := response["subject"]
	skip := response["skip"]
	requested_scope := response["requested_scope"]
	client := response["client"]

	if skip.(bool) {
		resp, resp_err := AcceptLoginRequest(challenge, map[string]interface{}{
			"grant_scope": response["requested_scope"],
			"session": map[string]interface{}{
				"access_token": map[string]interface{}{
					"role": map[string]interface{}{
						"userId":   User_id,
						"userRole": User_role,
					},
				},
			},
		})
		if resp_err != nil {
			r.HTML(w, http.StatusOK, "error", map[string]interface{}{"response_err": resp_err})
			return
		}

		redirect_url := resp["redirect_to"]
		http.Redirect(w, req, redirect_url.(string), http.StatusFound)
	}

	r.HTML(w, http.StatusOK, "consent", map[string]interface{}{
		"challenge":       challenge,
		"requested_scope": requested_scope,
		"user":            subject,
		"client":          client,
	})
}

func (r *Render) HandleConsent(w http.ResponseWriter, req *http.Request, _ httprouter.Params) {
	req.ParseForm()
	challenge := req.Form.Get("challenge")
	if challenge == "/" {
		r.HTML(w, http.StatusOK, "error", map[string]interface{}{"challenge": challenge, "error": "challenge 为空"})
		return
	}

	submit := req.Form.Get("submit")

	if submit == "Deny access" {
		resp, resp_err := RejectConsentRequest(challenge, map[string]interface{}{
			"error":             "access_denied",
			"error_description": "The resource owner denied the request",
		})

		redirect_url := resp["redirect_to"]
		http.Redirect(w, req, redirect_url.(string), http.StatusFound)
		return
	}

	Grant_scope := req.Form["grant_scope"]
	if len(req.Form["grant_scope"]) == 0 {
		r.HTML(w, http.StatusOK, "error", map[string]interface{}{"grant_scope": "Grant_scope", "error": "grant_scope 为空"})
		return
	}

	remember := req.Form.Get("remember")
	remember_bool, _ := strconv.ParseBool(remember)

	resq, resp_err := AcceptConsentRequest(challenge, map[string]interface{}{
		"grant_scope":  Grant_scope,
		"session":      map[string]interface{}{},
		"remember":     remember_bool,
		"remember_for": 3600,
	})
	if resp_err != nil {
		r.HTML(w, http.StatusOK, "error", map[string]interface{}{"response_err": resp_err})
		return
	}

	redirect_url := resq["redirect_to"]
	http.Redirect(w, req, redirect_url.(string), http.StatusFound)
}

// func typeof(v interface{}) string {
// 	return fmt.Sprintf("%T", v)
// }

func main() {
	// r := Render{
	// 	render.New(render.Options{
	// 		Layout: "layout",
	// 	})}
	// CSRF := csrf.Protect([]byte("32-byte-long-auth-key"))
	// body_csrf := map[string]interface{}{"headers": map[string]interface{}{"Authorization": "Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ=="}}
	// fmt.Println(body_csrf, "-----body_csrf-----")
	// body_content, _ := json.Marshal(body_csrf)
	// content := string(body_content)

	// request, err := http.NewRequest("GET", url, strings.NewReader(content))
	r := Render{render.New()}
	router := httprouter.New()

	router.ServeFiles("/static/*filepath", http.Dir("./static")) //加载templates文件
	router.GET("/", r.Index)
	// router.GET("/hello/:name", r.Hello)
	router.GET("/login", r.Login)
	router.POST("/login", r.HandleLogin)
	router.GET("/consent", r.Consent)
	router.POST("/consent", r.HandleConsent)

	log.Fatal(http.ListenAndServe(":8080", router))
}
