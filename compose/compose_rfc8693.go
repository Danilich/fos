package compose

import (
	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/oauth2"
	"github.com/ory/fosite/handler/rfc8693"
)

//exchange
func OAuth2TokenExchangeFactory(config *Config, storage interface{}, strategy interface{}) interface{} {
	return &rfc8693.Handler{
		AccessTokenStrategy:      strategy.(oauth2.AccessTokenStrategy),
		AccessTokenStorage:       storage.(oauth2.AccessTokenStorage),
		AccessTokenLifespan:      config.GetAccessTokenLifespan(),
		ScopeStrategy:            config.GetScopeStrategy(),
		AudienceMatchingStrategy: config.GetAudienceStrategy(),
		RefreshTokenStrategy:     strategy.(oauth2.RefreshTokenStrategy),
		RefreshTokenLifespan:     config.GetRefreshTokenLifespan(),
		RefreshTokenScopes:       config.GetRefreshTokenScopes(),
		CoreStorage:              storage.(oauth2.CoreStorage),
		CoreStrategy:             strategy.(oauth2.CoreStrategy),
		Store:                    storage.(fosite.Storage),
	}
}
