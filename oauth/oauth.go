package oauth

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/wgarcia4190/bookstore_utils_go/rest_errors"
	"github.com/wgarcia4190/go-rest/gorest"
)

const (
	headerXPublic   = "X-Public"
	headerXClientId = "X-Client-Id"
	headerXCallerId = "X-Caller-Id"

	paramAccessToken = "access_token"
)

var (
	oauthRestClient = gorest.NewBuilder().
		SetBaseUrl("http://localhost:8080").
		SetConnectionTimeout(200 * time.Millisecond).
		SetResponseTimeout(200 * time.Millisecond).
		Build()
)

type accessToken struct {
	Id       string `json:"id"`
	UserId   int64  `json:"user_id"`
	ClientId int64  `json:"client_id"`
}

func IsPublic(request *http.Request) bool {
	if request == nil {
		return true
	}
	return request.Header.Get(headerXPublic) == "true"
}

func GetCallerId(request *http.Request) int64 {
	return getNumericHeader(request, headerXCallerId)
}

func GetClientId(request *http.Request) int64 {
	return getNumericHeader(request, headerXClientId)
}

func AuthenticateRequest(request *http.Request) *rest_errors.RestErr {
	if request == nil {
		return nil
	}

	cleanRequest(request)

	accessTokenId := strings.TrimSpace(request.URL.Query().Get(paramAccessToken))
	if accessTokenId == "" {
		return nil
	}

	at, err := getAccessToken(accessTokenId)
	if err != nil {
		if err.Status == http.StatusNotFound {
			return nil
		}
		return err
	}

	request.Header.Add(headerXClientId, fmt.Sprintf("%v", at.ClientId))
	request.Header.Add(headerXCallerId, fmt.Sprintf("%v", at.UserId))

	return nil
}

func cleanRequest(request *http.Request) {
	if request == nil {
		return
	}

	request.Header.Del(headerXClientId)
	request.Header.Del(headerXCallerId)
}

func getAccessToken(accessTokenId string) (*accessToken, *rest_errors.RestErr) {
	url := fmt.Sprintf("/oauth/access_token/%s", accessTokenId)
	response, err := oauthRestClient.Get(url)
	if err != nil || response == nil {
		return nil, rest_errors.NewInternalServerError("invalid client response when trying to login user", err)
	}

	if response.StatusCode > 299 {
		var restErr rest_errors.RestErr

		if err := json.Unmarshal(response.Body, &restErr); err != nil {
			return nil, rest_errors.NewInternalServerError("invalid error interface when trying to login user", err)
		}
		return nil, &restErr
	}

	var at accessToken
	if err := json.Unmarshal(response.Bytes(), &at); err != nil {
		return nil, rest_errors.NewInternalServerError("error when trying to unmarshal users login response", rest_errors.NewError("json parsing error"))
	}
	return &at, nil
}

func getNumericHeader(request *http.Request, header string) int64 {
	if request == nil {
		return 0
	}

	callerId, err := strconv.ParseInt(request.Header.Get(header), 10, 64)
	if err != nil {
		return 0
	}

	return callerId
}
