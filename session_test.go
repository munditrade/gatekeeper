//go:build !e2e
// +build !e2e

/*
Copyright 2015 All rights reserved.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/gogatekeeper/gatekeeper/pkg/apperrors"
	"github.com/stretchr/testify/assert"
)

func TestGetIndentity(t *testing.T) {
	testCases := []struct {
		Request       func(token string) *http.Request
		Ok            bool
		ProxySettings func(c *Config)
	}{
		{
			Request: func(token string) *http.Request {
				return &http.Request{
					Header: http.Header{
						"Authorization": []string{fmt.Sprintf("Bearer %s", token)},
					},
				}
			},
			Ok: true,
			ProxySettings: func(c *Config) {
				c.SkipAuthorizationHeaderIdentity = false
			},
		},
		{
			Request: func(token string) *http.Request {
				return &http.Request{
					Header: http.Header{
						"Authorization": []string{"Basic QWxhZGRpbjpPcGVuU2VzYW1l"},
					},
				}
			},
			Ok: false,
			ProxySettings: func(c *Config) {
				c.SkipAuthorizationHeaderIdentity = false
			},
		},
		{
			Request: func(token string) *http.Request {
				return &http.Request{
					Header: http.Header{
						"Authorization": []string{fmt.Sprintf("Test %s", token)},
					},
				}
			},
			Ok: false,
			ProxySettings: func(c *Config) {
				c.SkipAuthorizationHeaderIdentity = false
			},
		},
		{
			Request: func(token string) *http.Request {
				return &http.Request{
					Header: http.Header{},
				}
			},
			Ok: false,
			ProxySettings: func(c *Config) {
				c.SkipAuthorizationHeaderIdentity = false
			},
		},
		{
			Request: func(token string) *http.Request {
				return &http.Request{
					Header: http.Header{},
				}
			},
			Ok: false,
			ProxySettings: func(c *Config) {
				c.SkipAuthorizationHeaderIdentity = true
			},
		},
		{
			Request: func(token string) *http.Request {
				return &http.Request{
					Header: http.Header{
						"Authorization": []string{fmt.Sprintf("Bearer %s", token)},
					},
				}
			},
			Ok: false,
			ProxySettings: func(c *Config) {
				c.SkipAuthorizationHeaderIdentity = true
			},
		},
		{
			Request: func(token string) *http.Request {
				return &http.Request{
					Header: http.Header{
						"Authorization": []string{"Basic QWxhZGRpbjpPcGVuU2VzYW1l"},
					},
				}
			},
			Ok: false,
			ProxySettings: func(c *Config) {
				c.SkipAuthorizationHeaderIdentity = true
			},
		},
	}

	for idx, testCase := range testCases {
		c := newFakeKeycloakConfig()
		testCase := testCase
		testCase.ProxySettings(c)

		p, idp, _ := newTestProxyService(c)
		token, err := newTestToken(idp.getLocation()).getToken()
		assert.NoError(t, err)

		user, err := p.getIdentity(testCase.Request(token))

		if err != nil && testCase.Ok {
			t.Errorf("test case %d should not have errored", idx)
			continue
		}

		if err == nil && !testCase.Ok {
			t.Errorf("test case %d should not have errored", idx)
			continue
		}

		if err != nil && !testCase.Ok {
			continue
		}

		if user.rawToken != token {
			t.Errorf("test case %d the tokens are not the same", idx)
		}
	}
}

func TestGetTokenInRequest(t *testing.T) {
	defaultName := newDefaultConfig().CookieAccessName
	token, err := newTestToken("test").getToken()
	assert.NoError(t, err)
	testCases := []struct {
		Token                           string
		AuthScheme                      string
		Error                           error
		SkipAuthorizationHeaderIdentity bool
	}{
		{
			Token:                           "",
			AuthScheme:                      "",
			Error:                           apperrors.ErrSessionNotFound,
			SkipAuthorizationHeaderIdentity: false,
		},
		{
			Token:                           token,
			AuthScheme:                      "",
			Error:                           nil,
			SkipAuthorizationHeaderIdentity: false,
		},
		{
			Token:                           token,
			AuthScheme:                      "Bearer",
			Error:                           nil,
			SkipAuthorizationHeaderIdentity: false,
		},
		{
			Token:                           "",
			AuthScheme:                      "",
			Error:                           apperrors.ErrSessionNotFound,
			SkipAuthorizationHeaderIdentity: true,
		},
		{
			Token:                           token,
			AuthScheme:                      "Bearer",
			Error:                           apperrors.ErrSessionNotFound,
			SkipAuthorizationHeaderIdentity: true,
		},
		{
			Token:                           token,
			AuthScheme:                      "",
			Error:                           nil,
			SkipAuthorizationHeaderIdentity: true,
		},
		{
			Token:                           "QWxhZGRpbjpPcGVuU2VzYW1l",
			AuthScheme:                      "Basic",
			Error:                           apperrors.ErrSessionNotFound,
			SkipAuthorizationHeaderIdentity: false,
		},
		{
			Token:                           token,
			AuthScheme:                      "Test",
			Error:                           apperrors.ErrSessionNotFound,
			SkipAuthorizationHeaderIdentity: false,
		},
	}
	for idx, testCase := range testCases {
		req := newFakeHTTPRequest(http.MethodGet, "/")
		if testCase.Token != "" {
			if testCase.AuthScheme != "" {
				req.Header.Set(authorizationHeader, testCase.AuthScheme+" "+testCase.Token)
			} else {
				req.AddCookie(&http.Cookie{
					Name:   defaultName,
					Path:   req.URL.Path,
					Domain: req.Host,
					Value:  testCase.Token,
				})
			}
		}
		access, bearer, err := getTokenInRequest(req, defaultName, testCase.SkipAuthorizationHeaderIdentity)
		switch testCase.Error {
		case nil:
			assert.NoError(t, err, "case %d should not have thrown an error", idx)
			assert.Equal(t, testCase.AuthScheme == "Bearer", bearer)
			assert.Equal(t, token, access)
		default:
			assert.Equal(t, testCase.Error, err, "case %d, expected error: %s", idx, testCase.Error)
		}
	}
}

func TestGetRefreshTokenFromCookie(t *testing.T) {
	proxy, _, _ := newTestProxyService(nil)
	cases := []struct {
		Cookies  *http.Cookie
		Expected string
		Ok       bool
	}{
		{
			Cookies: &http.Cookie{},
		},
		{
			Cookies: &http.Cookie{
				Name:   "not_a_session_cookie",
				Path:   "/",
				Domain: "127.0.0.1",
			},
		},
		{
			Cookies: &http.Cookie{
				Name:   "kc-state",
				Path:   "/",
				Domain: "127.0.0.1",
				Value:  "refresh_token",
			},
			Expected: "refresh_token",
			Ok:       true,
		},
	}

	for _, testCase := range cases {
		req := newFakeHTTPRequest(http.MethodGet, "/")
		req.AddCookie(testCase.Cookies)
		token, err := proxy.getRefreshTokenFromCookie(req)
		switch testCase.Ok {
		case true:
			assert.NoError(t, err)
			assert.NotEmpty(t, token)
			assert.Equal(t, testCase.Expected, token)
		default:
			assert.Error(t, err)
			assert.Empty(t, token)
		}
	}
}
