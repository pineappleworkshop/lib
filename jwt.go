package main

import (
	"fmt"
	"net/http"
	"reflect"
	"strings"

	"github.com/dgrijalva/jwt-go"
	"github.com/labstack/echo"
	"github.com/labstack/echo/middleware"
)

// types for jwtCustomMiddleware
type (
	CustomJWTConfig struct {
		Skipper        middleware.Skipper
		BeforeFunc     middleware.BeforeFunc
		GetProduct     func(echo.Context) (string, error)
		GetJWTSecret   func(string) (string, error)
		SuccessHandler JWTSuccessHandler
		ErrorHandler   JWTErrorHandler
		// SigningKey     interface{}
		SigningMethod string
		ContextKey    string
		Claims        jwt.Claims
		TokenLookup   string
		AuthScheme    string
	}

	JWTSuccessHandler func(echo.Context)
	JWTErrorHandler   func(error) error
	jwtExtractor      func(echo.Context) (string, error)
)

// Algorithms
const (
	AlgorithmHS256 = "HS256"
)

// Errors
var (
	ErrJWTMissing = echo.NewHTTPError(http.StatusBadRequest, "missing or malformed jwt")
)

var (
	// DefaultJWTConfig is the default JWT auth middleware config.
	DefaultCustomJWTConfig = CustomJWTConfig{
		Skipper:       middleware.DefaultSkipper,
		SigningMethod: AlgorithmHS256,
		ContextKey:    "user",
		TokenLookup:   "header:" + echo.HeaderAuthorization,
		AuthScheme:    "Bearer",
		Claims:        jwt.MapClaims{},
	}
)

// customJWTmiddleware to source secrets in the product context
func CustomJWTWithConfig(config CustomJWTConfig) echo.MiddlewareFunc {
	// Defaults
	if config.Skipper == nil {
		config.Skipper = middleware.DefaultJWTConfig.Skipper
	}
	if config.SigningMethod == "" {
		config.SigningMethod = middleware.DefaultJWTConfig.SigningMethod
	}
	if config.ContextKey == "" {
		config.ContextKey = middleware.DefaultJWTConfig.ContextKey
	}
	if config.Claims == nil {
		config.Claims = middleware.DefaultJWTConfig.Claims
	}
	if config.TokenLookup == "" {
		config.TokenLookup = middleware.DefaultJWTConfig.TokenLookup
	}
	if config.AuthScheme == "" {
		config.AuthScheme = middleware.DefaultJWTConfig.AuthScheme
	}

	// Initialize
	parts := strings.Split(config.TokenLookup, ":")
	extractor := jwtFromHeader(parts[1], config.AuthScheme)
	switch parts[0] {
	case "query":
		extractor = jwtFromQuery(parts[1])
	case "cookie":
		extractor = jwtFromCookie(parts[1])
	}

	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			product, err := config.GetProduct(c)
			if err != nil {
				return err
			}

			jwtSecret, err := config.GetJWTSecret(product)
			if err != nil {
				return err
			}

			keyFunc := func(t *jwt.Token) (interface{}, error) {
				if t.Method.Alg() != config.SigningMethod {
					return nil, fmt.Errorf("unexpected jwt signing method=%v", t.Header["alg"])
				}
				return []byte(jwtSecret), nil
			}

			if config.Skipper(c) {
				return next(c)
			}

			if config.BeforeFunc != nil {
				config.BeforeFunc(c)
			}

			auth, err := extractor(c)
			if err != nil {
				if config.ErrorHandler != nil {
					return config.ErrorHandler(err)
				}
				return err
			}

			token := new(jwt.Token)
			if _, ok := config.Claims.(jwt.MapClaims); ok {
				token, err = jwt.Parse(auth, keyFunc)
			} else {
				t := reflect.ValueOf(config.Claims).Type().Elem()
				claims := reflect.New(t).Interface().(jwt.Claims)
				token, err = jwt.ParseWithClaims(auth, claims, keyFunc)
			}
			if err == nil && token.Valid {
				// Store user information from token into context.
				c.Set(config.ContextKey, token)
				if config.SuccessHandler != nil {
					config.SuccessHandler(c)
				}
				return next(c)
			}

			if config.ErrorHandler != nil {
				return config.ErrorHandler(err)
			}
			return &echo.HTTPError{
				Code:     http.StatusUnauthorized,
				Message:  "invalid or expired jwt",
				Internal: err,
			}
		}
	}
}

// jwtFromHeader returns a `jwtExtractor` that extracts token from the request header.
func jwtFromHeader(header string, authScheme string) jwtExtractor {
	return func(c echo.Context) (string, error) {
		auth := c.Request().Header.Get(header)
		l := len(authScheme)
		if len(auth) > l+1 && auth[:l] == authScheme {
			return auth[l+1:], nil
		}
		return "", ErrJWTMissing
	}
}

// jwtFromQuery returns a `jwtExtractor` that extracts token from the query string.
func jwtFromQuery(param string) jwtExtractor {
	return func(c echo.Context) (string, error) {
		token := c.QueryParam(param)
		if token == "" {
			return "", ErrJWTMissing
		}
		return token, nil
	}
}

// jwtFromCookie returns a `jwtExtractor` that extracts token from the named cookie.
func jwtFromCookie(name string) jwtExtractor {
	return func(c echo.Context) (string, error) {
		cookie, err := c.Cookie(name)
		if err != nil {
			return "", ErrJWTMissing
		}
		return cookie.Value, nil
	}
}
