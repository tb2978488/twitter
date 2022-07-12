package main

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"github.com/gin-gonic/gin"
	"io/ioutil"
	"math/rand"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

var (
	consumerKey    = "OSqfh35sUqKnf91CCxy1HDe7z"                          //key
	consumerSecret = "yCyLsQhbFViIeleySesRwEl6dtFS5Sb43dSEOqxZw22BHYepqS" //Secretkey
	httpurl        = "https://twitter.com/oauth/request_token"            //url，必需全部小写。
	//httpurl    = "http://localhost:9890/test.php" //url，必需全部小写。
	httpMethod = "GET"

	//twitter 参数
	times                  = time.Now().Unix()
	oauth_consumer_key     = consumerKey
	oauth_nonce            = times + int64(rand.Intn(100000))
	oauth_signature_method = "HMAC-SHA1"
	oauth_timestamp        = times
	oauth_version          = "1.0"
	key                    = consumerSecret + "&"
)

func main() {
	//bind()
	r := gin.Default()
	r.GET("/", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"msg": "success",
		})
	})
	//获取twitter参数 oauth_token
	r.GET("/bind", func(c *gin.Context) {
		c.Redirect(http.StatusMovedPermanently, bind())
	})
	r.POST("/sciconf", func(c *gin.Context) {
		oauth_token := c.DefaultPostForm("oauth_token", "")
		oauth_verifier := c.DefaultPostForm("oauth_verifier", "")
		if oauth_token == "" || oauth_verifier == "" {
			c.JSON(200, gin.H{
				"msg":  "error",
				"code": "1001",
			})
			return
		}
		httpurl := "https://api.twitter.com/oauth/access_token?"
		params := fmt.Sprintf("oauth_consumer_key=%s&oauth_nonce=%v&oauth_signature_method=%s&oauth_timestamp=%v&oauth_verifier=%s&oauth_token=%s&oauth_version=%s", consumerKey, oauth_nonce, oauth_signature_method, oauth_timestamp, oauth_verifier, oauth_token, oauth_version)
		signature_text := url.QueryEscape(httpMethod) + "&" + url.QueryEscape(httpurl) + "&" + url.QueryEscape(params)
		oauth_signature := get_signature(signature_text, key)
		client := &http.Client{}
		req, _ := http.NewRequest(httpMethod, httpurl, nil)
		req.Header.Add(
			"Authorization",
			"OAuth oauth_consumer_key="+oauth_consumer_key+
				",oauth_nonce="+strconv.FormatInt(oauth_nonce, 10)+
				",oauth_signature_method="+oauth_signature_method+
				",oauth_timestamp="+strconv.FormatInt(oauth_timestamp, 10)+
				",oauth_verifier="+oauth_verifier+
				",oauth_token="+oauth_token+
				",oauth_version="+oauth_version+
				",oauth_signature="+oauth_signature,
		)
		resp, _ := client.Do(req)
		body, _ := ioutil.ReadAll(resp.Body)
		values, err := url.ParseQuery(string(body))
		user_id := values.Get("user_id")
		if err != nil || user_id == "" {
			c.JSON(200, gin.H{
				"msg":     err,
				"user_id": "",
				"code":    "1001",
			})
		} else {
			c.JSON(200, gin.H{
				"msg":     "success",
				"user_id": user_id,
				"code":    "1000",
			})
		}
	})
	r.GET("/test", func(c *gin.Context) {
		q := "oauth_token=1544156702089523200-OyMmGb7iK0kPeYiwmH8meYP23ngUKb&oauth_token_secret=X3f1ueLqwaWKG9nIeV9z2jeKJR9MucHogasfd2g0hnxy3&user_id=1544156702089523200&screen_name=zhaozhaomeng3"
		values, err := url.ParseQuery(q)
		user_id := values.Get("user_id")
		if err != nil || user_id == "" {
			c.JSON(200, gin.H{
				"msg":     err,
				"user_id": "",
				"code":    "1001",
			})
		} else {
			c.JSON(200, gin.H{
				"msg":     "success",
				"user_id": user_id,
				"code":    "1000",
			})
		}

	})

	r.Run(":9000")
}

func bind() string {
	//参数，此次请求中的除了oauth_signature以外的所有参数按照字母顺序升序排列，如果参数名相同，那么按照参数值的字母顺序升序排列。
	params := fmt.Sprintf("oauth_consumer_key=%s&oauth_nonce=%v&oauth_signature_method=%s&oauth_timestamp=%v&oauth_version=%s", consumerKey, oauth_nonce, oauth_signature_method, oauth_timestamp, oauth_version)
	signature_text := url.QueryEscape(httpMethod) + "&" + url.QueryEscape(httpurl) + "&" + url.QueryEscape(params)
	oauth_signature := get_signature(signature_text, key)
	client := &http.Client{}
	req, _ := http.NewRequest(httpMethod, httpurl, nil)
	req.Header.Add("Authorization",
		"OAuth oauth_consumer_key="+oauth_consumer_key+
			",oauth_nonce="+strconv.FormatInt(oauth_nonce, 10)+
			",oauth_signature_method="+oauth_signature_method+
			",oauth_timestamp="+strconv.FormatInt(oauth_timestamp, 10)+
			",oauth_version="+oauth_version+
			",oauth_signature="+oauth_signature,
	)
	resp, _ := client.Do(req)
	body, _ := ioutil.ReadAll(resp.Body)
	return "https://api.twitter.com/oauth/authorize?" + string(body)
}

/*
加密
*/
func get_signature(value, keyStr string) string {
	key := []byte(keyStr)
	mac := hmac.New(sha1.New, key)
	mac.Write([]byte(value))
	//进行base64编码
	res := base64.StdEncoding.EncodeToString(mac.Sum(nil))
	return url.QueryEscape(res)
	//return res
}
