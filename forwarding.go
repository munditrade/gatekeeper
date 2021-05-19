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
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"time"

	"go.uber.org/zap"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
	"gopkg.in/square/go-jose.v2/jwt"
)

// proxyMiddleware is responsible for handles reverse proxy request to the upstream endpoint
func (r *oauthProxy) proxyMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		next.ServeHTTP(w, req)

		// @step: retrieve the request scope
		scope := req.Context().Value(contextScopeName)
		var sc *RequestScope
		if scope != nil {
			sc = scope.(*RequestScope)
			if sc.AccessDenied {
				return
			}
		}

		// @step: add the proxy forwarding headers
		req.Header.Add("X-Forwarded-For", realIP(req))
		req.Header.Set("X-Forwarded-Host", req.Host)
		req.Header.Set("X-Forwarded-Proto", req.Header.Get("X-Forwarded-Proto"))

		if len(r.config.CorsOrigins) > 0 {
			// if CORS is enabled by Gatekeeper, do not propagate CORS requests upstream
			req.Header.Del("Origin")
		}
		// @step: add any custom headers to the request
		for k, v := range r.config.Headers {
			req.Header.Set(k, v)
		}

		// @note: by default goproxy only provides a forwarding proxy, thus all requests have to be absolute and we must update the host headers
		req.URL.Host = r.endpoint.Host
		req.URL.Scheme = r.endpoint.Scheme
		// Restore the unprocessed original path, so that we pass upstream exactly what we received
		// as the resource request.
		if sc != nil {
			req.URL.Path = sc.Path
			req.URL.RawPath = sc.RawPath
		}
		if v := req.Header.Get("Host"); v != "" {
			req.Host = v
			req.Header.Del("Host")
		} else if !r.config.PreserveHost {
			req.Host = r.endpoint.Host
		}

		if isUpgradedConnection(req) {
			r.log.Debug("upgrading the connnection", zap.String("client_ip", req.RemoteAddr))
			if err := tryUpdateConnection(req, w, r.endpoint); err != nil {
				r.log.Error("failed to upgrade connection", zap.Error(err))
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			return
		}

		r.upstream.ServeHTTP(w, req)
	})
}

// forwardProxyHandler is responsible for signing outbound requests
// nolint:funlen
func (r *oauthProxy) forwardProxyHandler() func(*http.Request, *http.Response) {
	ctx := context.Background()

	if r.config.SkipOpenIDProviderTLSVerify {
		tr := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		sslcli := &http.Client{Transport: tr}
		ctx = context.WithValue(ctx, oauth2.HTTPClient, sslcli)
	}

	conf := r.newOAuth2Config(r.config.RedirectionURL)

	// the loop state
	var state struct {
		// the access token
		token jwt.JSONWebToken
		// the refresh token if any
		refresh string
		// the expiry time of the access token
		expiration time.Time
		// whether we need to login
		login bool
		// whether we should wait for expiration
		wait bool
		// RawToken
		rawToken string
		// Subject
		subject string
	}
	state.login = true

	// create a routine to refresh the access tokens or login on expiration
	go func() {
		for {
			state.wait = false

			// step: do we have a access token
			if state.login {
				// step: login into the service

				var resp *oauth2.Token
				var err error

				switch r.config.ForwardingGrantType {
				case GrantTypeClientCreds:
					r.log.Info(
						"requesting access token for client (client_credentials grant) ",
						zap.String("client_id", r.config.ClientID),
					)

					conf := &clientcredentials.Config{
						ClientID:     r.config.ClientID,
						ClientSecret: r.config.ClientSecret,
						Scopes:       r.config.Scopes,
						TokenURL:     r.provider.Endpoint().TokenURL,
					}
					resp, err = conf.Token(ctx)
				case GrantTypeUserCreds:
					r.log.Info(
						"requesting access token for user (password grant) ",
						zap.String("username", r.config.ForwardingUsername),
					)

					resp, err = conf.PasswordCredentialsToken(
						ctx,
						r.config.ForwardingUsername,
						r.config.ForwardingPassword,
					)
				default:
					r.log.Info(
						"Chosen grant type is not supported",
						zap.String("forwarding_grant_type", r.config.ForwardingGrantType),
					)
				}

				if err != nil {
					r.log.Error("failed to login to authentication service", zap.Error(err))
					// step: back-off and reschedule
					<-time.After(time.Duration(5) * time.Second)
					continue
				}

				state.rawToken = resp.AccessToken
				// step: parse the token
				token, err := jwt.ParseSigned(resp.AccessToken)
				if err != nil {
					r.log.Error("failed to parse the access token", zap.Error(err))
					// step: we should probably hope and reschedule here
					<-time.After(time.Duration(5) * time.Second)
					continue
				}

				stdClaims := &jwt.Claims{}

				err = token.UnsafeClaimsWithoutVerification(stdClaims)

				if err != nil {
					r.log.Error("unable to parse access token for claims", zap.Error(err))
					continue
				}

				// step: update the loop state
				state.token = *token
				state.expiration = stdClaims.Expiry.Time()
				state.subject = stdClaims.Subject
				state.wait = true
				state.login = false
				state.refresh = resp.RefreshToken

				r.log.Debug(
					"successfully retrieved access token for subject",
					zap.String("access token", state.rawToken),
					zap.String("subject", state.subject),
					zap.String("expires", state.expiration.Format(time.RFC3339)),
				)

				r.log.Info(
					"successfully retrieved access token for subject",
					zap.String("subject", state.subject),
					zap.String("expires", state.expiration.Format(time.RFC3339)),
				)
			} else {
				r.log.Debug(
					"access token is about to expiry",
					zap.String("access token", state.rawToken),
					zap.String("subject", state.subject),
				)

				r.log.Info(
					"access token is about to expiry",
					zap.String("subject", state.subject),
				)

				// step: if we a have a refresh token, we need to login again
				if state.refresh != "" && r.config.ForwardingGrantType != GrantTypeClientCreds {
					r.log.Debug(
						"attempting to refresh the access token",
						zap.String("access token", state.rawToken),
						zap.String("refresh token", state.refresh),
						zap.String("subject", state.subject),
						zap.String("expires", state.expiration.Format(time.RFC3339)),
					)

					r.log.Info(
						"attempting to refresh the access token",
						zap.String("subject", state.subject),
						zap.String("expires", state.expiration.Format(time.RFC3339)),
					)

					// step: attempt to refresh the access
					token, rawToken, newRefreshToken, expiration, _, err := getRefreshedToken(conf, r.config, state.refresh)
					state.rawToken = rawToken

					if err != nil {
						state.login = true
						switch err {
						case ErrRefreshTokenExpired:
							r.log.Debug(
								"the refresh token has expired, need to login again",
								zap.String("refresh token", state.refresh),
								zap.String("subject", state.subject),
							)
							r.log.Warn(
								"the refresh token has expired, need to login again",
								zap.String("subject", state.subject),
							)
						default:
							r.log.Error("failed to refresh the access token", zap.Error(err))
						}
						continue
					}

					// step: update the state
					state.token = token
					state.expiration = expiration
					state.wait = true
					state.login = false
					if newRefreshToken != "" {
						state.refresh = newRefreshToken
					}

					// step: add some debugging
					r.log.Debug(
						"successfully refreshed the access token",
						zap.String("new access token", state.rawToken),
						zap.String("refresh token", state.refresh),
						zap.String("subject", state.subject),
						zap.String("expires", state.expiration.Format(time.RFC3339)),
					)

					r.log.Info(
						"successfully refreshed the access token",
						zap.String("subject", state.subject),
						zap.String("expires", state.expiration.Format(time.RFC3339)),
					)
				} else {
					r.log.Info(
						"session does not support refresh token, acquiring new token",
						zap.String("subject", state.subject),
					)

					// we don't have a refresh token, we must perform a login again
					state.wait = false
					state.login = true
				}
			}

			// wait for an expiration to come close
			if state.wait {
				// set the expiration of the access token within a random 85% of actual expiration
				duration := getWithin(state.expiration, 0.85)
				r.log.Info(
					"waiting for expiration of access token",
					zap.String("token_expiration", state.expiration.Format(time.RFC3339)),
					zap.String("renewal_duration", duration.String()),
				)

				<-time.After(duration)
			}
		}
	}()

	return func(req *http.Request, resp *http.Response) {
		hostname := req.Host
		req.URL.Host = hostname
		// is the host being signed?
		if len(r.config.ForwardingDomains) == 0 || containsSubString(hostname, r.config.ForwardingDomains) {
			req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", state.rawToken))
			req.Header.Set("X-Forwarded-Agent", prog)
		}
	}
}
