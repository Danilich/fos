package rfc8693

import (
	"context"
	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/oauth2"
	"github.com/ory/fosite/storage"
	"github.com/pkg/errors"
	"github.com/tidwall/sjson"
	"strings"
	"time"
)

type Handler struct {
	AccessTokenStrategy      oauth2.AccessTokenStrategy
	AccessTokenStorage       oauth2.AccessTokenStorage
	AccessTokenLifespan      time.Duration
	ScopeStrategy            fosite.ScopeStrategy
	AudienceMatchingStrategy fosite.AudienceMatchingStrategy
	RefreshTokenStrategy     oauth2.RefreshTokenStrategy
	RefreshTokenLifespan     time.Duration
	RefreshTokenScopes       []string
	oauth2.CoreStrategy
	oauth2.CoreStorage
	Store fosite.Storage
}

func (c *Handler) HandleTokenEndpointRequest(ctx context.Context, request fosite.AccessRequester) error {

	//	grant_type
	//		REQUIRED. The value "urn:ietf:params:oauth:grant-type:token-
	//		exchange" indicates that a token exchange is being performed.
	if !request.GetGrantTypes().ExactOne("token-exchange") {
		return errors.WithStack(fosite.ErrUnknownRequest)
	}

	client := request.GetClient()

	if client.IsPublic() {
		return errors.WithStack(fosite.ErrInvalidGrant.WithHint("The OAuth 2.0 Client is marked as public and is thus not allowed to use authorization grant \"urn:ietf:params:oauth:grant-type:token-exchange\"."))
	}

	if !client.GetGrantTypes().Has("token-exchange") {
		return errors.WithStack(fosite.ErrUnauthorizedClient.WithHint("The OAuth 2.0 Client is not allowed to use authorization grant \"urn:ietf:params:oauth:grant-type:token-exchange\"."))
	}

	// From https://tools.ietf.org/html/rfc8693#section-2.1:
	//
	//	subject_token
	//		REQUIRED.  A security token that represents the identity of the
	//		party on behalf of whom the request is being made.  Typically, the
	//		subject of this token will be the subject of the security token
	//		issued in response to the request.
	form := request.GetRequestForm()
	subjectToken := form.Get("subject_token")
	if subjectToken == "" {
		return errors.WithStack(fosite.ErrInvalidRequest.WithHintf("Mandatory parameter subject_token is missing."))
	}

	// From https://tools.ietf.org/html/rfc8693#section-2.1:
	//
	//	subject_token_type
	//		REQUIRED.  An identifier, as described in Section 3, that
	//		indicates the type of the security token in the "subject_token"
	//		parameter.
	subjectTokenType := form.Get("subject_token_type")
	if subjectTokenType == "" {
		return errors.WithStack(fosite.ErrInvalidRequest.WithHintf("Mandatory parameter subject_token_type is missing."))
	} else if subjectTokenType != "urn:ietf:params:oauth:token-type:access_token" {
		return errors.WithStack(fosite.ErrInvalidRequest.WithHintf("Currently only \"subject_token_type=urn:ietf:params:oauth:token-type:access_token\" is supported but got \"%s\".", subjectTokenType))
	}

	sig := c.CoreStrategy.AccessTokenSignature(subjectToken)
	or, err := c.CoreStorage.GetAccessTokenSession(ctx, sig, request.GetSession())
	if err != nil {
		return errors.WithStack(fosite.ErrRequestUnauthorized.WithDebug(err.Error()))
	} else if err := c.CoreStrategy.ValidateAccessToken(ctx, or, subjectToken); err != nil {
		return err
	}

	var subjectTokenClientId string
	if or.GetSubjectTokenClient() == nil {
		subjectTokenClientId = or.GetClient().GetID()
	} else {
		subjectTokenClientId = or.GetSubjectTokenClient().GetID()
	}

	if client.GetID() == subjectTokenClientId {
		return errors.WithStack(fosite.ErrRequestForbidden.WithHint("Clients are not allowed to perform a token exchange on their own tokens"))
	}

	subjectTokenClient, err := c.Store.GetClient(ctx, subjectTokenClientId)
	if err != nil {
		return errors.WithStack(fosite.ErrInvalidClient.WithHint("The subjects token OAuth2 Client does not exist."))
	}

	subjectClient, ok := subjectTokenClient.(fosite.TokenExchangeClient)
	if !ok {
		return errors.WithStack(fosite.ErrUnauthorizedClient.WithHint("The OAuth 2.0 Client is not allowed to perform a token exchange for the given subject token."))
	}

	tokenExchangeRequest, ok := request.(fosite.TokenExchangeAccessRequester)
	if !ok {
		return errors.WithStack(fosite.ErrInvalidRequestObject)
	}

	tokenExchangeRequest.SetSubjectTokenClient(subjectClient)

	for _, scope := range request.GetRequestedScopes() {
		if !c.ScopeStrategy(client.GetScopes(), scope) &&
			!c.ScopeStrategy(or.GetGrantedScopes(), scope) {
			return errors.WithStack(fosite.ErrInvalidScope.WithHintf("The OAuth 2.0 Client is not allowed to request scope \"%s\".", scope))
		}
	}

	if err := c.AudienceMatchingStrategy(client.GetAudience(), request.GetRequestedAudience()); err != nil {
		return errors.WithStack(fosite.ErrInvalidTarget)

	}

	//add act to Session
	metToString := ""

	if or.GetSession().GetExtra()["act"] != nil {
		metToString = or.GetSession().GetExtra()["act"].(string)
	}

	if !strings.Contains(metToString, client.GetID()) {
		act := addNewActor(metToString, client.GetID())

		request.GetSession().SetExtra("act", act)
	}

	request.GetSession().SetExpiresAt(fosite.AccessToken, time.Now().UTC().Add(c.AccessTokenLifespan))
	if c.RefreshTokenLifespan > -1 {
		request.GetSession().SetExpiresAt(fosite.RefreshToken, time.Now().UTC().Add(c.RefreshTokenLifespan).Round(time.Second))
	}

	return nil
}

// PopulateTokenEndpointResponse implements https://tools.ietf.org/html/rfc8693#section-2.2 (currently impersonation only)
func (c *Handler) PopulateTokenEndpointResponse(ctx context.Context, request fosite.AccessRequester, response fosite.AccessResponder) error {

	if !request.GetGrantTypes().ExactOne("token-exchange") {
		return errors.WithStack(fosite.ErrUnknownRequest)
	}

	if !request.GetClient().GetGrantTypes().Has("token-exchange") {
		return errors.WithStack(fosite.ErrUnauthorizedClient.WithHint("The OAuth 2.0 Client is not allowed to use authorization grant \"urn:ietf:params:oauth:grant-type:token-exchange\"."))
	}

	token, signature, err := c.AccessTokenStrategy.GenerateAccessToken(ctx, request)
	if err != nil {
		return err
	} else if err := c.AccessTokenStorage.CreateAccessTokenSession(ctx, signature, request.Sanitize([]string{})); err != nil {
		return err
	}

	if request.GetGrantedScopes().HasOneOf(c.RefreshTokenScopes...) {
		refresh, refreshSignature, err := c.RefreshTokenStrategy.GenerateRefreshToken(ctx, request)
		if err != nil {
			return errors.WithStack(fosite.ErrServerError.WithDebug(err.Error()))
		}
		if refreshSignature != "" {
			if err := c.CoreStorage.CreateRefreshTokenSession(ctx, refreshSignature, request.Sanitize([]string{})); err != nil {
				if rollBackTxnErr := storage.MaybeRollbackTx(ctx, c.CoreStorage); rollBackTxnErr != nil {
					err = rollBackTxnErr
				}
				return errors.WithStack(fosite.ErrServerError.WithDebug(err.Error()))
			}
		}
		response.SetExtra("refresh_token", refresh)
	}

	response.SetAccessToken(token)
	response.SetTokenType("bearer")
	response.SetExpiresIn(oauth2.GetExpiresIn(request, fosite.AccessToken, c.AccessTokenLifespan, time.Now().UTC()))
	response.SetScopes(request.GetGrantedScopes())
	response.SetIssuedTokenType("urn:ietf:params:oauth:token-type:access_token")

	return nil
}
func (c *Handler) CanSkipClientAuth(requester fosite.AccessRequester) bool {
	return true
}

func (c *Handler) CanHandleTokenEndpointRequest(requester fosite.AccessRequester) bool {

	// grant_type REQUIRED.
	// Value MUST be set to "client_credentials".
	return requester.GetGrantTypes().ExactOne("token-exchange")
}

func addNewActor(jsons string, client string) string {
	type ClientID struct {
		ID string `json:"client_id"`
	}
	const clientID = "client_id"

	actPath := findLastActorPath(jsons)
	var res string

	if jsons == "" {
		res, _ = sjson.Set(jsons, clientID, client)
		return res
	}

	res, _ = sjson.Set(jsons, actPath, ClientID{ID: client})
	return res
}

func findLastActorPath(jsons string) string {
	const act = "act"
	actPath := ""
	actCount := strings.Count(jsons, act)

	y := strings.Repeat("act.", actCount)
	actPath = strings.TrimSuffix(y, ".")

	if actCount == 0 {
		actPath = act
	} else {
		actPath = actPath + ".act"
	}

	return actPath
}
