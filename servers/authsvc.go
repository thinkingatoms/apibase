/*
Copyright © 2022 THINKINGATOMS LLC <atom@thinkingatoms.com>
*/

package servers

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/go-chi/chi/v5"
	"github.com/gorilla/sessions"
	"github.com/markbates/goth"
	"github.com/markbates/goth/gothic"
	"github.com/markbates/goth/providers/google"
	"github.com/markbates/goth/providers/linkedin"
	"github.com/rs/zerolog/log"
	"github.com/thinkingatoms/apibase/ez"
	"github.com/thinkingatoms/apibase/models"
	errors "golang.org/x/xerrors"
	"net/http"
	"strings"
	"time"
)

type authService struct {
	server      *Server
	auth        models.Auth
	adminRoles  map[string]bool
	smsClient   *models.SMSClient
	emailClient *models.EmailClient
}

func CreateAuth(server *Server) (models.Auth, error) {
	db := server.GetDb()
	if db == nil {
		return nil, errors.New("no database connection")
	}

	name := "auth"
	if !server.HasSubConfig(name) {
		return nil, nil
	}
	return models.AuthFromConfig(db, server.GetSubConfig(name), server.GetSecret), nil
}

func RegisterAuthService(server *Server, auth models.Auth, adminRoles string) {
	roles := make(map[string]bool)
	for _, role := range strings.Split(adminRoles, ",") {
		roles[role] = true
	}
	s := authService{
		server:     server,
		auth:       auth,
		adminRoles: roles,
	}
	if server.HasSubConfig("sms") {
		s.smsClient = models.SMSFromConfig(server.GetSubConfig("sms"))
	}
	if server.HasSubConfig("email") {
		s.emailClient = models.EmailClientFromConfig(server.GetSubConfig("email"))
	}
	s.EnrichRouter(server.Router)
	server.AddSetup(s.Setup)
}

func (self *authService) Setup(ctx context.Context) error {
	err := self.auth.CleanAuthSessions(ctx)
	if err != nil {
		log.Error().Msg("failed to start cleaning auth sessions")
		return err
	}
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Hour):
			err = self.auth.CleanAuthSessions(ctx)
			if err != nil {
				return err
			}
		}
	}
}

func (self *authService) EnrichRouter(router *chi.Mux) {
	gothic.Store = self.buildStore()
	pathPrefix := "/auth/v1"
	router.Route(pathPrefix, func(r chi.Router) {
		r.Route("/entitlement", func(re chi.Router) {
			re.Use(self.adminOnly)
			re.Get("/", self.dumpEntitlementsHandler)
			re.Post("/", self.addEntitlementHandler)
			re.Delete("/", self.removeEntitlementHandler)
		})
		r.Route("/role", func(re chi.Router) {
			re.Use(self.adminOnly)
			re.Post("/", self.addRoleHandler)
			re.Delete("/", self.removeRoleHandler)
		})
		r.Post("/message", self.messageHandler)
		// refresh JWT token
		r.Get("/refresh", self.auth.IsLoggedIn(self.refreshTokenHandler))
		// authenticate based on client_id/client_secret
		r.Post("/generate-phone", self.createPhoneHandler)
		r.Post("/phone", self.phoneHandler)
		r.Post("/generate-client", self.auth.IsLoggedIn(self.createClientHandler))
		r.Post("/client", self.clientHandler)

		r.Post("/signup", self.signupHandler)
		r.Get("/verify-email/{code}", self.emailHandler)
		r.Post("/login", self.loginHandler)
		r.Post("/logout", self.auth.IsValidJWT(self.logoutHandler))
		// retrieve user profile
		r.Get("/profile", self.auth.IsLoggedIn(self.profileHandler))

		r.Post("/oauth", self.oauthHandler)
		cred := self.auth.GetOauthProviderCred("google")
		if cred != nil {
			goth.UseProviders(
				google.New(
					cred.ClientID,
					cred.ClientSecret,
					self.server.GetPublicURL()+pathPrefix+"/google/callback",
					"email", "profile"),
			)
			r.Get("/google", self.oauthInit("google"))
			r.Get("/google/callback", self.oauthCallback("google"))
		}
		cred = self.auth.GetOauthProviderCred("linkedin")
		if cred != nil {
			goth.UseProviders(
				linkedin.New(
					cred.ClientID,
					cred.ClientSecret,
					self.server.GetPublicURL()+pathPrefix+"/linkedin/callback",
					"r_liteprofile", "r_emailaddress"),
			)
			r.Get("/linkedin", self.oauthInit("linkedin"))
			r.Get("/linkedin/callback", self.oauthCallback("linkedin"))
		}
	})
}

func (self *authService) adminOnly(next http.Handler) http.Handler {
	return self.auth.IsValidJWT(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		payload := ctx.Value(models.RequestAuthKey).(models.JWTPayload)
		for _, role := range strings.Split(payload.GetRoles(), ",") {
			if self.adminRoles[role] {
				next.ServeHTTP(w, r)
				return
			}
		}
		ez.AccessDeniedHandler(w, r, errors.New("admin only"))
	})
}

func (self *authService) buildStore() *sessions.CookieStore {
	store := sessions.NewCookieStore(self.server.GetSecret())
	store.MaxAge(self.auth.GetCookieMaxAge())
	store.Options.Path = "/"
	store.Options.HttpOnly = true
	store.Options.Secure = true
	return store
}

func (self *authService) dumpEntitlementsHandler(w http.ResponseWriter, r *http.Request) {
	ez.DoOr500(w, r, ez.WriteObjectAsJSON)(self.auth.DumpEntitlements(r.Context()))
}

func (self *authService) addEntitlementHandler(w http.ResponseWriter, r *http.Request) {
	var cred models.Login
	err := json.NewDecoder(r.Body).Decode(&cred)
	if err != nil {
		ez.InternalServerErrorHandler(w, r, err)
		return
	}
	var ret bool
	ret, err = self.auth.AddEntitlement(r.Context(), cred.Email, cred.Name)
	if err != nil {
		ez.InternalServerErrorHandler(w, r, err)
		return
	}
	_, _ = w.Write(ez.Bool2bytes(ret))
	return
}

func (self *authService) removeEntitlementHandler(w http.ResponseWriter, r *http.Request) {
	var cred models.Login
	err := json.NewDecoder(r.Body).Decode(&cred) // email + name (of role)
	if err != nil {
		ez.InternalServerErrorHandler(w, r, err)
		return
	}
	var ret bool
	ret, err = self.auth.RemoveEntitlement(r.Context(), cred.Email, cred.Name)
	if err != nil {
		ez.InternalServerErrorHandler(w, r, err)
		return
	}
	_, _ = w.Write(ez.Bool2bytes(ret))
	return
}

func (self *authService) addRoleHandler(w http.ResponseWriter, r *http.Request) {
	var cred models.Login
	err := json.NewDecoder(r.Body).Decode(&cred)
	if err != nil {
		ez.InternalServerErrorHandler(w, r, err)
		return
	}
	err = self.auth.AddRole(r.Context(), cred.Name)
	if err != nil {
		ez.InternalServerErrorHandler(w, r, err)
		return
	}
	_, _ = w.Write([]byte("true"))
}

func (self *authService) removeRoleHandler(w http.ResponseWriter, r *http.Request) {
	var cred models.Login
	err := json.NewDecoder(r.Body).Decode(&cred)
	if err != nil {
		ez.InternalServerErrorHandler(w, r, err)
		return
	}
	err = self.auth.RemoveRole(r.Context(), cred.Name)
	if err != nil {
		ez.InternalServerErrorHandler(w, r, err)
		return
	}
	_, _ = w.Write([]byte("true"))
}

func (self *authService) oauthInit(provider string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		r = r.WithContext(context.WithValue(r.Context(), "provider", provider))
		gothic.BeginAuthHandler(w, r)
	}
}

func (self *authService) oauthCallback(provider string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		r = r.WithContext(context.WithValue(r.Context(), "provider", provider))
		user, err := gothic.CompleteUserAuth(w, r)
		if err != nil {
			ez.InternalServerErrorHandler(w, r, err)
			return
		}
		http.SetCookie(w, &http.Cookie{
			Name:   gothic.SessionName,
			Value:  "",
			Path:   "/",
			MaxAge: -1,
		})
		var userStatus models.UserStatus
		switch provider {
		case "google":
			if v, ok := user.RawData["verified_email"]; ok && v.(bool) {
				userStatus = models.UserStatusVerified
			} else {
				err = errors.New("unverified per " + provider)
				ez.AccessDeniedHandler(w, r, err)
				return
			}
		case "linkedin":
			userStatus = models.UserStatusVerified
			if user.RawData == nil {
				raw := make(map[string]interface{})
				raw["email"] = user.Email
				raw["family_name"] = user.LastName
				raw["given_name"] = user.FirstName
				raw["name"] = user.Name
				raw["nickname"] = user.NickName
				raw["picture"] = user.AvatarURL
				raw["id"] = user.UserID
				raw["location"] = user.Location
				raw["description"] = user.Description
				user.RawData = raw
			}
		default:
			err = errors.New("unsupported oauth provider")
			ez.InternalServerErrorHandler(w, r, err)
			return
		}
		u := &models.AuthUser{
			EntityType:       models.UserEntityType,
			EntityUUID:       self.auth.GenerateRandomUUID(),
			DisplayName:      strings.TrimSpace(user.Name),
			EntityStatus:     userStatus,
			Email:            strings.TrimSpace(strings.ToLower(user.Email)),
			AuthMethod:       provider,
			Validation:       user.UserID,
			HashedValidation: user.UserID,
			Details:          user.RawData,
		}
		ctx := r.Context()
		var email string
		email, err = self.auth.UpsertUser(ctx, u, false)
		if err != nil {
			ez.AccessDeniedHandler(w, r, err)
			return
		}
		ez.DoOr500(w, r, self.payloadHandler)(self.auth.CreatePayload(ctx, email))
	}
}

type oauthUser struct {
	AuthMethod     string `json:"auth_method"`
	IdToken        string `json:"id_token"`
	AccessToken    string `json:"access_token"`
	ServerAuthCode string `json:"server_auth_code"`
}

func (self *authService) oauthHandler(w http.ResponseWriter, r *http.Request) {
	var o oauthUser
	err := json.NewDecoder(r.Body).Decode(&o)
	if err != nil {
		ez.InternalServerErrorHandler(w, r, err)
		return
	}
	var user goth.User
	var userStatus models.UserStatus
	switch o.AuthMethod {
	case "google":
		sess := google.Session{
			AccessToken: o.AccessToken,
			IDToken:     o.IdToken,
		}
		provider, err := goth.GetProvider("google")
		if err != nil {
			ez.InternalServerErrorHandler(w, r, err)
			return
		}
		user, err = provider.FetchUser(&sess)
		if err != nil {
			ez.InternalServerErrorHandler(w, r, err)
			return
		}
		if v, ok := user.RawData["verified_email"]; ok && v.(bool) {
			userStatus = models.UserStatusVerified
		} else {
			err = errors.New("unverified per " + provider.Name())
			ez.AccessDeniedHandler(w, r, err)
			return
		}
	default:
		ez.BadRequestHandler(w, r, errors.New(fmt.Sprintf("unsupported oauth provider: %+v", o)))
		return
	}
	u := &models.AuthUser{
		EntityType:       models.UserEntityType,
		EntityUUID:       self.auth.GenerateRandomUUID(),
		DisplayName:      strings.TrimSpace(user.Name),
		EntityStatus:     userStatus,
		Email:            strings.TrimSpace(strings.ToLower(user.Email)),
		AuthMethod:       o.AuthMethod,
		Validation:       user.UserID,
		HashedValidation: user.UserID,
		Details:          user.RawData,
	}
	ctx := r.Context()
	var email string
	email, err = self.auth.UpsertUser(ctx, u, false)
	if err != nil {
		ez.AccessDeniedHandler(w, r, err)
		return
	}
	ez.DoOr500(w, r, self.payloadHandler)(self.auth.CreatePayload(ctx, email))
}

func (self *authService) createClientHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	payload := ctx.Value(models.RequestAuthKey).(models.JWTPayload)
	ez.DoOr500(w, r, ez.WriteObjectAsJSON)(self.auth.CreateClientCred(r.Context(), payload.GetID()))
}

func (self *authService) clientHandler(w http.ResponseWriter, r *http.Request) {
	var cred models.ClientCredential
	err := json.NewDecoder(r.Body).Decode(&cred)
	if err != nil {
		ez.InternalServerErrorHandler(w, r, err)
		return
	}
	ez.DoOr401(w, r, self.payloadHandler)(self.auth.CheckClientCred(r.Context(), &cred))
}

func (self *authService) signupHandler(w http.ResponseWriter, r *http.Request) {
	var cred models.Login
	err := json.NewDecoder(r.Body).Decode(&cred)
	if err != nil {
		ez.InternalServerErrorHandler(w, r, err)
		return
	}
	ctx := r.Context()
	var verificationCode string
	verificationCode, err = self.auth.CreateLogin(ctx, &cred, r.RemoteAddr)
	if err != nil {
		ez.AccessDeniedHandler(w, r, err)
		return
	}
	err = self.sendVerificationEmail(ctx, cred.Email, verificationCode)
	if err != nil {
		ez.InternalServerErrorHandler(w, r, err)
		return
	}
	ez.WriteBytes(w, r, ez.Bool2bytes(true))
}

func (self *authService) sendVerificationEmail(ctx context.Context, email, verificationCode string) error {
	subject := "Verify your email"
	body := fmt.Sprintf("Please verify your email by clicking the link below:\n\n%s/auth/v1/verify-email/%s\n\nThank you!\n\n",
		self.server.GetPublicURL(), verificationCode)
	return self.emailClient.Send(ctx, email, subject, body)
}

func (self *authService) loginHandler(w http.ResponseWriter, r *http.Request) {
	var cred models.Login
	err := json.NewDecoder(r.Body).Decode(&cred)
	if err != nil {
		ez.InternalServerErrorHandler(w, r, err)
		return
	}
	ez.DoOr401(w, r, self.payloadHandler)(self.auth.CheckLogin(r.Context(), &cred))
}

func (self *authService) refreshTokenHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	payload := ctx.Value(models.RequestAuthKey).(models.JWTPayload)
	if payload.GetRoles() != models.JWT_REFRESH {
		err := errors.New("invalid refresh token")
		ez.AccessDeniedHandler(w, r, err)
		return
	}
	ez.DoOr401(w, r, self.payloadHandler)(self.auth.CheckRefresh(r.Context(), payload.GetID(), payload.GetSession()))
}

func (self *authService) logoutHandler(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:    "access_token",
		Value:   "",
		Expires: time.Unix(0, 0),
	})
	http.SetCookie(w, &http.Cookie{
		Name:    "refresh_token",
		Value:   "",
		Expires: time.Unix(0, 0),
	})
	ret, err := self.auth.Logout(r.Context(), r.Context().Value(models.RequestAuthKey).(models.JWTPayload))
	if err != nil {
		ez.InternalServerErrorHandler(w, r, err)
		return
	}
	_, _ = w.Write(ez.Bool2bytes(ret))
}

func (self *authService) profileHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	payload := ctx.Value(models.RequestAuthKey).(models.JWTPayload)
	ez.DoOr500(w, r, ez.WriteObjectAsJSON)(self.auth.GetProfile(ctx, payload.GetID()))
}

func (self *authService) payloadHandler(w http.ResponseWriter, r *http.Request, payload models.JWTPayload) {
	accessToken, err := self.auth.CreateAccessToken(payload)
	if err != nil {
		ez.InternalServerErrorHandler(w, r, err)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:  "access_token",
		Value: accessToken,
	})
	var refreshToken string
	refreshToken, err = self.auth.CreateRefreshToken(payload)
	if err != nil {
		ez.InternalServerErrorHandler(w, r, err)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:  "refresh_token",
		Value: refreshToken,
	})
	ez.WriteObjectAsJSON(w, r, map[string]string{
		"id":            payload.GetID(),
		"session":       payload.GetSession(),
		"roles":         payload.GetRoles(),
		"access_token":  accessToken,
		"refresh_token": refreshToken,
	})
}

func (self *authService) createPhoneHandler(w http.ResponseWriter, r *http.Request) {
	var o models.PhoneCode
	err := json.NewDecoder(r.Body).Decode(&o)
	if err != nil {
		ez.InternalServerErrorHandler(w, r, err)
		return
	}
	var phone string
	phone, err = o.GetPhone()
	if err != nil {
		ez.BadRequestHandler(w, r, err)
		return
	}
	code := ez.RandIntSeq(6)
	if o.Code != "" {
		payload, err := self.auth.LoadJWT(r)
		if err != nil {
			ez.AccessDeniedHandler(w, r, errors.New("only admins can set code"))
			return
		}
		if self.auth.HasRole(payload, "admin") {
			code = o.Code
		} else {
			ez.AccessDeniedHandler(w, r, errors.New("only admins can set code"))
			return
		}
	}
	err = self.auth.CreateAuthCode(r.Context(), "phone", phone, code, r.RemoteAddr, time.Minute*5)
	if err != nil {
		ez.InternalServerErrorHandler(w, r, err)
		return
	}
	msg := fmt.Sprintf("%s verification code: %s", self.server.Name, code)
	err = self.smsClient.Send(phone, msg)
	if err != nil {
		ez.InternalServerErrorHandler(w, r, err)
		return
	}
	_, _ = w.Write(ez.Bool2bytes(true))
}

func (self *authService) phoneHandler(w http.ResponseWriter, r *http.Request) {
	var o models.PhoneCode
	err := json.NewDecoder(r.Body).Decode(&o)
	if err != nil {
		ez.InternalServerErrorHandler(w, r, err)
		return
	}
	ez.DoOr401(w, r, self.payloadHandler)(self.auth.CheckPhone(r.Context(), &o))
}

func (self *authService) messageHandler(w http.ResponseWriter, r *http.Request) {
	var o models.AuthMessage
	err := json.NewDecoder(r.Body).Decode(&o)
	if err != nil {
		ez.InternalServerErrorHandler(w, r, err)
		return
	}
	err = self.auth.Message(r.Context(), &o)
	if err != nil {
		ez.InternalServerErrorHandler(w, r, err)
		return
	}
	if self.emailClient != nil {
		msg, err := json.Marshal(o)
		if err == nil {
			err = self.emailClient.Send(r.Context(), "", "__message__", string(msg))
			if err != nil {
				log.Error().Err(err).Msgf("failed to email message: %+v", o)
			}
		} else {
			log.Error().Err(err).Msgf("failed to marshal message: %+v", o)
		}
	}
	_, _ = w.Write(ez.Bool2bytes(true))
}

func (self *authService) emailHandler(w http.ResponseWriter, r *http.Request) {
	code := chi.URLParam(r, "code")
	ez.DoOr401(w, r, self.payloadHandler)(self.auth.CheckEmailVerification(r.Context(), code))
}
