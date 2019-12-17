package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"policy_manager/cloud-api/parnurzeal/gorequest"
	"strconv"
	"time"
	"strings"
)

func sha256hex(s string) string {
	b := sha256.Sum256([]byte(s))
	return hex.EncodeToString(b[:])
}

func hmacsha256(s, key string) string {
	hashed := hmac.New(sha256.New, []byte(key))
	hashed.Write([]byte(s))
	return string(hashed.Sum(nil))
}

func main() {
	secretId := ""
	secretKey := ""
	host := "faceid.tencentcloudapi.com"
	algorithm := "TC3-HMAC-SHA256"
	service := "faceid"
	version := "2018-03-01"
	action := "DetectAuth"
	region := "ap-guangzhou"
	var timestamp int64 = time.Now().Unix()
	//var timestamp int64 = 1551113065

	//步骤 1 : 拼接规范请求串 step 1: build canonical request string
	httpRequestMethod := "POST"
	canonicalURI := "/"
	canonicalQueryString := ""
	canonicalHeaders := "content-type:application/json; charset=utf-8\n" + "host:" + host + "\n"
	signedHeaders := "content-type;host"
	payload := `{"RuleId": "0"}`
	hashedRequestPayload := sha256hex(payload)
	canonicalRequest := fmt.Sprintf("%s\n%s\n%s\n%s\n%s\n%s",
		httpRequestMethod,
		canonicalURI,
		canonicalQueryString,
		canonicalHeaders,
		signedHeaders,
		hashedRequestPayload)
	fmt.Println("canonicalRequest:",canonicalRequest)
	fmt.Println("-------------------------------")

	//步骤 2 : 拼接待签名字符串  step 2: build string to sign
	date := time.Unix(timestamp, 0).UTC().Format("2006-01-02")
	credentialScope := fmt.Sprintf("%s/%s/tc3_request", date, service)
	hashedCanonicalRequest := sha256hex(canonicalRequest)
	string2sign := fmt.Sprintf("%s\n%d\n%s\n%s",
		algorithm,
		timestamp,
		credentialScope,
		hashedCanonicalRequest)

	fmt.Println("string2sign:",string2sign)
	// 步骤 3：计算签名  step 3: sign string
	secretDate := hmacsha256(date, "TC3"+secretKey)
	secretService := hmacsha256(service, secretDate)
	secretSigning := hmacsha256("tc3_request", secretService)
	signature := hex.EncodeToString([]byte(hmacsha256(string2sign, secretSigning)))

	// 步骤 4：拼接请求头参数 Authorization  step 4: build authorization
	authorization := fmt.Sprintf("%s Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		algorithm,
		secretId,
		credentialScope,
		signedHeaders,
		signature)

	curl := fmt.Sprintf(`curl -X POST https://%s\
 -H "Authorization: %s"\
 -H "Content-Type: application/json; charset=utf-8"\
 -H "Host: %s" -H "X-TC-Action: %s"\
 -H "X-TC-Timestamp: %d"\
 -H "X-TC-Version: %s"\
 -H "X-TC-Region: %s"\
 -d '%s'`, host, authorization, host, action, timestamp, version, region, payload)
	fmt.Println(curl)
	reqUrl := "https://faceid.tencentcloudapi.com"
	reqBody := `{"RuleId":"0"}`

	// 注意: 生成curl后在postman上发送请求返回成功, 代码请求缺不成功, 请更换request库重试
	action = strings.TrimSpace(action)
	resp, rspBody, err := gorequest.New().Post(reqUrl).
		Set("Content-Type", "application/json").
		Set("Authorization", authorization).
		Set("Host", host).
		Set("X-TC-Action", "DetectAuth").
		Set("X-TC-Timestamp", strconv.Itoa(int(timestamp))).
		Set("X-TC-Version",version).
		Set("X-TC-Region",region).
		Send(payload).
		Timeout(time.Second * 10).
		End()
	fmt.Println("url=%s, rspbody=%s, resp:%v, err:%v", reqUrl, rspBody, resp, err)

}
