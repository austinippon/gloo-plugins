package pkg

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/solo-io/ext-auth-plugins/api"
	"github.com/solo-io/go-utils/contextutils"
	"go.uber.org/zap"
)

var (
	UnexpectedConfigError = func(typ interface{}) error {
		return errors.New(fmt.Sprintf("unexpected config type %T", typ))
	}
	_ api.ExtAuthPlugin = new(CustomerIOAuthPlugin)
)

type CustomerIOAuthPlugin struct{}

type Config struct {
	SigningSecret string
}

func (p *CustomerIOAuthPlugin) NewConfigInstance(ctx context.Context) (interface{}, error) {
	return &Config{}, nil
}

func (p *CustomerIOAuthPlugin) GetAuthService(ctx context.Context, configInstance interface{}) (api.AuthService, error) {
	config, ok := configInstance.(*Config)
	if !ok {
		return nil, UnexpectedConfigError(configInstance)
	}

	logger(ctx).Infow("Parsed CustomerIOAuthService config",
		zap.Any("requiredHeader", config.SigningSecret),
	)

	return &CustomerIOAuthService{
		SigningSecret: config.SigningSecret,
	}, nil
}

type CustomerIOAuthService struct {
	SigningSecret string
}

// You can use the provided context to perform operations that are bound to the services lifecycle.
func (c *CustomerIOAuthService) Start(context.Context) error {
	// no-op
	return nil
}

func (c *CustomerIOAuthService) Authorize(ctx context.Context, request *api.AuthorizationRequest) (*api.AuthorizationResponse, error) {
	timestamp := request.CheckRequest.GetAttributes().GetRequest().GetHttp().GetHeaders()["x-cio-timestamp"]
	signature := request.CheckRequest.GetAttributes().GetRequest().GetHttp().GetHeaders()["x-cio-signature"]
	body := []byte(request.CheckRequest.GetAttributes().GetRequest().GetHttp().GetBody())
	if ok, err := CheckSignature(c.SigningSecret, signature, timestamp, body); !ok {
		fmt.Println("Signatures didn't match:", err)
		return api.UnauthorizedResponse(), nil
	}
	fmt.Println("Signatures matched")
	return api.AuthorizedResponse(), nil
}

func CheckSignature(WebhookSigningSecret, XCIOSignature string, XCIOTimestamp string, RequestBody []byte) (bool, error) {
	signature, err := hex.DecodeString(XCIOSignature)
	if err != nil {
		return false, err
	}

	mac := hmac.New(sha256.New, []byte(WebhookSigningSecret))

	if _, err := mac.Write([]byte("v0:" + XCIOTimestamp + ":")); err != nil {
		return false, err
	}
	if _, err := mac.Write(RequestBody); err != nil {
		return false, err
	}

	computed := mac.Sum(nil)

	return hmac.Equal(computed, signature), nil
}

func logger(ctx context.Context) *zap.SugaredLogger {
	return contextutils.LoggerFrom(contextutils.WithLogger(ctx, "customerio_auth_plugin"))
}
