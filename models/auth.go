/*
Copyright © 2022 THINKINGATOMS LLC <atom@thinkingatoms.com>
*/

package models

import (
	"context"
	"github.com/gofrs/uuid"
	"github.com/golang-jwt/jwt/v4"
	"github.com/jackc/pgx/v4"
	"github.com/rs/zerolog/log"
	"github.com/thinkingatoms/apibase/ez"
	"golang.org/x/crypto/bcrypt"
	errors "golang.org/x/xerrors"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const defaultRefreshExpiry = 86400 * 30
const defaultSessionExpiry = 3600 * 24
const defaultAccessExpiry = 3600
const defaultFailCountExpiry = 3600 * 5
const maxFailCount = 10

func GetAccessToken(r *http.Request) (string, error) {
	cookie, err := r.Cookie("access_token")
	if errors.Is(err, http.ErrNoCookie) {
		bearer := r.Header.Get("Authorization")
		if bearer == "" {
			return "", errors.New("no authorization header")
		}
		parts := strings.Split(bearer, "Bearer")
		if len(parts) != 2 || parts[1] == "" {
			return "", errors.New("invalid authorization header")
		}
		return strings.TrimSpace(parts[1]), nil
	} else {
		return cookie.Value, nil
	}
}

func HashPassword(password string) string {
	return string(ez.ReturnOrPanic(bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)))
}

func CheckPassword(hash, password string) bool {
	if hash == password {
		return true
	}
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}

type JWTPayload interface {
	GetID() string
	GetSession() string
	GetRoles() string
}

type JWTTransformer interface {
	GetPayload(*jwt.Token) (JWTPayload, error)
	PutPayloadInAccess(*jwt.Token, JWTPayload) error
	PutPayloadInRefresh(*jwt.Token, JWTPayload) error
}

type JWTIssuer interface {
	NewJWT() *jwt.Token
	JWTKeyFunc(token *jwt.Token) (any, error)
	CreateAccessToken(payload JWTPayload) (string, error)
	CreateRefreshToken(JWTPayload) (string, error)
	IsValidJWT(http.HandlerFunc) http.HandlerFunc
	ValidateJWT(http.Handler) http.Handler
	IsAdmin(http.HandlerFunc) http.HandlerFunc
}

type Auth interface {
	JWTIssuer

	GetCookieMaxAge() int
	GenerateRandomUUID() uuid.UUID
	GetOauthProviderCred(string) *ClientCredential
	CreatePayload(context.Context, string) (JWTPayload, error)
	CheckRefresh(ctx context.Context, id string, token string) (JWTPayload, error)
	CreateClientCred(ctx context.Context, id string) (*ClientCredential, error)
	CheckClientCred(ctx context.Context, cred *ClientCredential) (JWTPayload, error)
	CheckLogin(context.Context, *Login) (JWTPayload, error)
	CreateUser(context.Context, *Login) (JWTPayload, error)
	UpsertUser(context.Context, *AuthUser, bool) (JWTPayload, error)
	GetProfile(context.Context, string) (*Profile, error)
	Logout(context.Context, JWTPayload) (bool, error)
	CleanAuthSessions(context.Context) error
	CreatePhoneCode(context.Context, string, string) (string, error)
	CheckPhoneCode(context.Context, *PhoneCode) (JWTPayload, error)

	// handler helpers

	IsActiveSession(context.Context, JWTPayload) (bool, error)
	IsLoggedIn(http.HandlerFunc) http.HandlerFunc

	// entitlement

	AddRole(context.Context, string) error
	RemoveRole(context.Context, string) error
	AddEntitlement(context.Context, string, string) (bool, error)
	RemoveEntitlement(context.Context, string, string) (bool, error)
	DumpEntitlements(context.Context) (map[string]map[string]bool, error)
}

type SimplePayload struct {
	id       string
	session  string
	roles    string
	rolesMap map[string]bool
}

func (self *SimplePayload) GetID() string {
	return self.id
}

func (self *SimplePayload) GetSession() string {
	return self.session
}

func (self *SimplePayload) GetRoles() string {
	return self.roles
}

func (self *SimplePayload) GetRolesMap() map[string]bool {
	if self.rolesMap == nil {
		rolesMap := make(map[string]bool)
		if self.roles != "" {
			for _, role := range strings.Split(self.roles, ",") {
				rolesMap[role] = true
			}
		}
		self.rolesMap = rolesMap
	}
	return self.rolesMap
}

type SimpleJWTIssuer struct {
	JWTTransformer
	secretGetter func() []byte
}

func (self *SimpleJWTIssuer) NewJWT() *jwt.Token {
	return jwt.New(jwt.SigningMethodHS256)
}

func (self *SimpleJWTIssuer) JWTKeyFunc(token *jwt.Token) (any, error) {
	if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
		return nil, errors.New("cannot parse JWT")
	}
	return self.secretGetter(), nil
}

func (self *SimpleJWTIssuer) IsValidJWT(handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tokenString, err := GetAccessToken(r)
		if err != nil {
			ez.AccessDeniedHandler(w, r, err)
			return
		}
		var token *jwt.Token
		token, err = jwt.Parse(tokenString, self.JWTKeyFunc)
		if err != nil {
			ez.AccessDeniedHandler(w, r, err)
			return
		}

		if token.Valid {
			payload, err := self.JWTTransformer.GetPayload(token)
			if err != nil {
				ez.InternalServerErrorHandler(w, r, err)
				return
			}
			r = r.WithContext(context.WithValue(r.Context(), RequestAuthKey, payload))
			handler.ServeHTTP(w, r)
			return
		}
		err = errors.New("not authenticated")
		ez.AccessDeniedHandler(w, r, err)
	}
}

func (self *SimpleJWTIssuer) IsAdmin(handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		payload := r.Context().Value(RequestAuthKey).(JWTPayload)
		for _, role := range strings.Split(payload.GetRoles(), ",") {
			if role == "admin" {
				handler.ServeHTTP(w, r)
				return
			}
		}
		ez.AccessDeniedHandler(w, r, errors.New("not admin"))
	}
}

func (self *SimpleJWTIssuer) ValidateJWT(next http.Handler) http.Handler {
	return self.IsValidJWT(next.(http.HandlerFunc))
}

func (self *SimpleJWTIssuer) CreateAccessToken(payload JWTPayload) (string, error) {
	token := self.NewJWT()
	key, err := self.JWTKeyFunc(token)
	if err != nil {
		return "", err
	}
	err = self.JWTTransformer.PutPayloadInAccess(token, payload)
	if err != nil {
		return "", err
	}
	return token.SignedString(key)
}

func (self *SimpleJWTIssuer) CreateRefreshToken(payload JWTPayload) (string, error) {
	token := self.NewJWT()
	key, err := self.JWTKeyFunc(token)
	if err != nil {
		return "", err
	}
	err = self.JWTTransformer.PutPayloadInRefresh(token, payload)
	if err != nil {
		return "", err
	}
	return token.SignedString(key)
}

type SimpleJWTTransformer struct {
	AccessExpiry  time.Duration `json:"access_expiry"`
	RefreshExpiry time.Duration `json:"refresh_expiry"`
}

func (self *SimpleJWTTransformer) GetPayload(token *jwt.Token) (JWTPayload, error) {
	claims := token.Claims.(jwt.MapClaims)
	return &SimplePayload{
		id:      claims["id"].(string),
		roles:   claims["roles"].(string),
		session: claims["sess"].(string),
	}, nil
}

func (self *SimpleJWTTransformer) PutPayloadInAccess(token *jwt.Token, payload JWTPayload) error {
	claims := token.Claims.(jwt.MapClaims)
	claims["exp"] = time.Now().Add(self.AccessExpiry * time.Second).Unix()
	claims["id"] = payload.GetID()
	claims["sess"] = payload.GetSession()
	claims["roles"] = payload.GetRoles()
	return nil
}

func (self *SimpleJWTTransformer) PutPayloadInRefresh(token *jwt.Token, payload JWTPayload) error {
	claims := token.Claims.(jwt.MapClaims)
	claims["exp"] = time.Now().Add(self.RefreshExpiry * time.Second).Unix()
	claims["id"] = payload.GetID()
	claims["sess"] = payload.GetSession()
	claims["roles"] = JWT_REFRESH
	return nil
}

type AuthDbImpl struct {
	JWTIssuer

	db DbConn

	MaxAge          int                          `json:"max_age"`
	Providers       map[string]map[string]string `json:"providers"`
	MaxFailCount    int                          `json:"max_fail_count"`
	FailCountExpiry time.Duration                `json:"fail_count_expiry"`
	SessionExpiry   time.Duration                `json:"session_expiry"`
}

func NewJWTIssuer(secretGetter func() []byte) JWTIssuer {
	return &SimpleJWTIssuer{
		JWTTransformer: &SimpleJWTTransformer{
			AccessExpiry:  defaultAccessExpiry,
			RefreshExpiry: defaultRefreshExpiry,
		},
		secretGetter: secretGetter,
	}
}

func AuthFromConfig(
	db DbConn,
	config map[string]any,
	secretGetter func() []byte,
) Auth {
	s := AuthDbImpl{
		JWTIssuer: NewJWTIssuer(secretGetter),
		db:        db,
	}
	ez.PanicIfErr(ez.MapToObject(config, &s))
	if s.FailCountExpiry == 0 {
		s.FailCountExpiry = defaultFailCountExpiry
	}
	if s.SessionExpiry == 0 {
		s.SessionExpiry = defaultSessionExpiry
	}
	return &s
}

func (s *AuthDbImpl) GetCookieMaxAge() int {
	return s.MaxAge
}

func (self *AuthDbImpl) AddRole(ctx context.Context, roleName string) error {
	sql := `
INSERT INTO auth.auth_role (role_name)
SELECT $1 WHERE NOT EXISTS (SELECT 1 FROM auth.auth_role WHERE role_name = $1)
RETURNING auth_role_id
`
	var ret int
	err := self.db.QueryRow(ctx, sql, roleName).Scan(&ret)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	return err
}

func (self *AuthDbImpl) RemoveRole(ctx context.Context, roleName string) error {
	sql := `
DELETE FROM auth.auth_role
WHERE role_name = $1
RETURNING auth_role_id
`
	var ret int
	err := self.db.QueryRow(ctx, sql, roleName).Scan(&ret)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	return err
}

func (self *AuthDbImpl) AddEntitlement(ctx context.Context, email, roleName string) (bool, error) {
	sql := `
WITH to_insert AS (
SELECT eu.entity_id, ar.auth_role_id, e.entitlement_id
FROM auth.end_user eu
CROSS JOIN auth.auth_role ar ON ar.role_name = $1
LEFT JOIN auth.entitlement e ON e.user_id = eu.entity_id AND e.role_id = ar.auth_role_id
AND e.user_id = e.target_id
WHERE eu.email = $2
)
INSERT INTO auth.entitlement (user_id, role_id, entitlement_id)
SELECT entity_id, auth_role_id, entity_id FROM to_insert WHERE entitlement_id IS NULL
RETURNING entitlement_id
`
	var ret int64
	err := self.db.QueryRow(ctx, sql, roleName, email).Scan(&ret)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	} else if err != nil {
		return false, err
	}
	return true, nil
}

func (self *AuthDbImpl) RemoveEntitlement(ctx context.Context, email, roleName string) (bool, error) {
	sql := `
WITH to_remove AS (
SELECT eu.entity_id, ar.auth_role_id
FROM auth.end_user eu
CROSS JOIN auth.auth_role ar ON ar.role_name = $1
WHERE eu.email = $2
)
DELETE FROM auth.entitlement e
USING to_remove r
WHERE e.user_id = r.entity_id AND e.role_id = r.auth_role_id AND e.user_id = e.target_id
RETURNING entitlement_id
`
	var ret int64
	err := self.db.QueryRow(ctx, sql, roleName, email).Scan(&ret)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	} else if err != nil {
		return false, err
	}
	return true, nil
}

func (self *AuthDbImpl) DumpEntitlements(ctx context.Context) (map[string]map[string]bool, error) {
	sql := `
SELECT e.email, r.role_name
FROM auth.entitlement e JOIN auth.auth_role r ON e.role_id = r.auth_role_id
JOIN auth.end_user eu ON e.user_id = eu.entity_id
WHERE e.user_id = e.target_id
`
	rows, err := self.db.Query(ctx, sql)
	if err != nil {
		return nil, err
	}
	roles := make(map[string]map[string]bool)
	for rows.Next() {
		var email, roleName string
		err = rows.Scan(&email, &roleName)
		if err != nil {
			return nil, err
		}
		if _, ok := roles[email]; !ok {
			roles[email] = make(map[string]bool)
		}
		roles[email][roleName] = true
	}
	if rows.Err() != nil {
		return nil, rows.Err()
	}
	return roles, nil
}

// JWT authentication

//goland:noinspection GoSnakeCaseUsage
const JWT_REFRESH = "__REFRESH__"

func (self *AuthDbImpl) CreatePayload(ctx context.Context, email string) (JWTPayload, error) {
	sql := `SELECT coalesce(string_agg(ar.role_name, ','), '') AS roles
FROM auth.end_user eu
LEFT JOIN auth.entitlement e ON eu.entity_id = e.user_id AND e.target_id = e.user_id
LEFT JOIN auth.auth_role ar ON e.role_id = ar.auth_role_id
WHERE eu.email = $1`
	var roles string
	err := self.db.QueryRow(ctx, sql, email).Scan(&roles)
	if err != nil {
		return nil, err
	}
	var userID int64
	sessionKey := self.GenerateRandomUUID().String()
	expiry := time.Now().Add(time.Second * self.SessionExpiry)
	err = self.db.QueryRow(ctx, `SELECT auth.f_create_auth_session($1, $2, $3)`,
		email, sessionKey, expiry).Scan(&userID)
	if err != nil {
		return nil, err
	}
	return &SimplePayload{
		id:      strconv.FormatInt(userID, 10),
		roles:   roles,
		session: sessionKey,
	}, nil
}

func (self *AuthDbImpl) GenerateRandomUUID() uuid.UUID {
	return uuid.NewV5(uuid.Nil, ez.RandSeq(32))
}

func (self *AuthDbImpl) CheckRefresh(ctx context.Context, id string, token string) (JWTPayload, error) {
	sql := `SELECT email FROM auth.end_user eu
JOIN auth.auth_session s ON eu.entity_id = s.entity_id
WHERE eu.entity_id = $1 AND s.session_key = $2
AND s.expiration_ts > current_timestamp`
	var email string
	err := self.db.QueryRow(ctx, sql, id, strings.TrimSpace(token)).Scan(&email)
	if err != nil {
		return nil, errors.New("not authorized to refresh: " + err.Error())
	}
	return self.CreatePayload(ctx, email)
}

type ClientCredential struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
}

func (self *AuthDbImpl) CreateClientCred(ctx context.Context, id string) (*ClientCredential, error) {
	sql := `SELECT eu.entity_uuid, coalesce(au.hashed_validation, ''), au.details
FROM auth.end_user eu
LEFT JOIN auth.auth_user au ON eu.entity_id = au.user_id
WHERE eu.entity_id = $1 AND au.auth_method = 'client'`
	var entityUUID, password string
	var details map[string]any
	err := self.db.QueryRow(ctx, sql, id).Scan(&entityUUID, &password, &details)
	if err != nil {
		return nil, err
	}
	if password == "" {
		password = self.GenerateRandomUUID().String()
		details = map[string]any{
			"secret": HashPassword(password),
		}
		var ret bool
		sql = `INSERT INTO auth.auth_user (user_id, auth_method, hashed_validation, details)
VALUES ($1, 'client', $2, $3) ON CONFLICT DO NOTHING RETURNING true`
		err = self.db.QueryRow(ctx, sql, id, password, details).Scan(&ret)
		if errors.Is(err, pgx.ErrNoRows) {
			sql = `SELECT eu.entity_id, u.entity_uuid, au.hashed_validation, au.details
FROM auth.end_user eu LEFT JOIN auth.auth_user au ON eu.entity_id = au.user_id
WHERE eu.entity_id = $1 AND au.auth_method = 'client'`
			err = self.db.QueryRow(ctx, sql, id).Scan(&id, &entityUUID, &password, &details)
			if err != nil {
				return nil, err
			}
		} else if err != nil {
			return nil, err
		}
	}
	return &ClientCredential{
		ClientID:     entityUUID,
		ClientSecret: details["secret"].(string),
	}, nil
}

func (self *AuthDbImpl) CheckClientCred(ctx context.Context, cred *ClientCredential) (JWTPayload, error) {
	sql := `SELECT eu.entity_id, eu.email, au.hashed_validation FROM auth.end_user eu
JOIN auth.auth_user au ON eu.entity_id = au.user_id
WHERE eu.entity_uuid = $1 AND au.auth_method = 'client'`
	var id int64
	var email, password string
	err := self.db.QueryRow(ctx, sql, cred.ClientID).Scan(&id, &email, &password)
	if err != nil {
		return nil, errors.New("invalid client id/secret: " + err.Error())
	}
	if !CheckPassword(cred.ClientSecret, password) {
		self.incFailCount(ctx, id)
		return nil, errors.New("invalid client id/secret")
	}
	return self.CreatePayload(ctx, email)
}

type Login struct {
	Email    string `json:"email,omitempty"`
	Password string `json:"password,omitempty"`
	Name     string `json:"name,omitempty"`
}

func (self *AuthDbImpl) CheckLogin(ctx context.Context, cred *Login) (JWTPayload, error) {
	sql := `SELECT eu.entity_id, au.hashed_validation FROM auth.end_user eu
JOIN auth.auth_user au ON eu.entity_id = au.user_id
WHERE eu.email = $1 AND au.auth_method = 'password'`
	var id int64
	var hashedValidation string
	email := strings.TrimSpace(strings.ToLower(cred.Email))
	err := self.db.QueryRow(ctx, sql, email).Scan(&id, &hashedValidation)
	if err != nil {
		return nil, err
	}
	if !CheckPassword(hashedValidation, cred.Password) {
		self.incFailCount(ctx, id)
		return nil, errors.New("invalid credentials")
	}
	return self.CreatePayload(ctx, email)
}

func (self *AuthDbImpl) GetOauthProviderCred(name string) *ClientCredential {
	if v, ok := self.Providers[name]; ok {
		return &ClientCredential{
			ClientID:     v["client_id"],
			ClientSecret: v["client_secret"],
		}
	}
	return nil
}

// User management

type AuthUser struct {
	EntityType       EntityType
	EntityUUID       uuid.UUID
	DisplayName      string
	Details          map[string]any
	EntityStatus     UserStatus
	Email            string
	AuthMethod       string
	Validation       string
	HashedValidation string
}

type UserStatus string

//goland:noinspection GoUnusedConst
const (
	UserStatusVerified   UserStatus = "verified"
	UserStatusUnverified            = "unverified"
)

type EntityType string

const (
	UserEntityType EntityType = "user"
)

func (self *AuthDbImpl) CreateUser(ctx context.Context, cred *Login) (JWTPayload, error) {
	cred.Email = strings.TrimSpace(strings.ToLower(cred.Email))
	u := &AuthUser{
		EntityType:       UserEntityType,
		EntityUUID:       uuid.NewV5(uuid.Nil, ez.RandSeq(64)),
		DisplayName:      strings.TrimSpace(cred.Name),
		EntityStatus:     UserStatusUnverified,
		Email:            cred.Email,
		AuthMethod:       "password",
		Validation:       strings.TrimSpace(cred.Password),
		HashedValidation: HashPassword(strings.TrimSpace(cred.Password)),
	}
	var err error
	_, err = self.UpsertUser(ctx, u, true)
	if err != nil {
		return nil, err
	}
	return self.CreatePayload(ctx, cred.Email)
}

func (self *AuthDbImpl) UpsertUser(ctx context.Context, u *AuthUser, forceNew bool) (JWTPayload, error) {
	sql := `SELECT eu.entity_id, eu.fail_count, eu.last_updated,
es.status_name, au.hashed_validation, au.details
FROM auth.end_user eu JOIN auth.entity_status es ON eu.entity_status_id = es.entity_status_id
LEFT JOIN auth.auth_user au ON eu.entity_id = au.user_id AND au.auth_method = $3
WHERE eu.email = $1 AND eu.entity_type = $2`
	u.Email = strings.TrimSpace(strings.ToLower(u.Email))
	var id int64
	var failCount int
	var lastUpdated time.Time
	var entityStatus UserStatus
	var hashedValidation *string
	var details *map[string]any
	err := self.db.QueryRow(ctx, sql,
		u.Email,
		u.EntityType,
		u.AuthMethod).Scan(&id, &failCount, &lastUpdated, &entityStatus, &hashedValidation, &details)
	if errors.Is(err, pgx.ErrNoRows) {
		if u.Details == nil {
			u.Details = make(map[string]any)
		}
		sql = `
WITH new_user AS (INSERT INTO auth.end_user
(entity_type, entity_uuid, display_name, entity_status_id, email, details)
SELECT $1, $2, $3, entity_status_id, $4, '{}'::jsonb
FROM auth.entity_status WHERE entity_type = $1 and status_name = $5
RETURNING entity_id)
INSERT INTO auth.auth_user (user_id, auth_method, hashed_validation, details)
SELECT entity_id, $6, $7, $8 FROM new_user RETURNING user_id`
		err = self.db.QueryRow(ctx, sql,
			u.EntityType, u.EntityUUID, u.DisplayName, u.Email, u.EntityStatus,
			u.AuthMethod, u.HashedValidation, u.Details).Scan(&id)
		if err != nil {
			return nil, err
		}
		return self.CreatePayload(ctx, u.Email)
	} else if err != nil {
		return nil, err
	}
	if forceNew && id != 0 {
		return nil, errors.New("invalid login")
	}
	checkTime := lastUpdated.Add(self.FailCountExpiry * time.Second)
	if failCount > self.MaxFailCount && time.Now().Before(checkTime) {
		return nil, errors.New("too many failed login attempts")
	}
	if entityStatus == UserStatusUnverified || u.EntityStatus == UserStatusUnverified {
		return nil, errors.New("user is not verified")
	}
	if hashedValidation == nil {
		var tmp bool
		sql = `INSERT INTO auth.auth_user (user_id, auth_method, hashed_validation, details)
VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING RETURNING true`
		err = self.db.QueryRow(ctx, sql, id, u.AuthMethod, u.HashedValidation, u.Details).Scan(&tmp)
		if errors.Is(err, pgx.ErrNoRows) {
			sql = `SELECT hashed_validation, details FROM auth.auth_user WHERE user_id = $1 AND auth_method = $2`
			err = self.db.QueryRow(ctx, sql, id, u.AuthMethod).Scan(&hashedValidation, &details)
		} else if err != nil {
			return nil, err
		} else {
			hashedValidation = &u.HashedValidation
			details = &u.Details
		}
	}
	if !CheckPassword(*hashedValidation, u.Validation) {
		self.incFailCount(ctx, id)
		return nil, errors.New("cannot validate login")
	} else if failCount > 0 {
		sql := `UPDATE auth.end_user SET fail_count = 0,
last_updated = current_timestamp, last_updated_by = session_user
WHERE entity_id = $1`
		_, err := self.db.Exec(ctx, sql, id)
		if err != nil {
			log.Error().Msgf("failed to reset fail count: %s", err.Error())
		}
	}
	if ez.SerializeMap(*details) != ez.SerializeMap(u.Details) {
		sql = `UPDATE auth.auth_user SET details = $1 WHERE user_id = $2 AND auth_method = $3`
		_, err = self.db.Exec(ctx, sql, u.Details, id, u.AuthMethod)
		if err != nil {
			return nil, err
		}
	}
	return self.CreatePayload(ctx, u.Email)
}

type Profile struct {
	Email       string         `json:"email"`
	DisplayName string         `json:"display_name"`
	UserStatus  UserStatus     `json:"user_status"`
	Details     map[string]any `json:"details"`
	AuthDetails map[string]any `json:"auth_details"`
}

func (self *AuthDbImpl) GetProfile(ctx context.Context, id string) (*Profile, error) {
	sql := `
WITH tmp AS (
SELECT jsonb_object_agg(au.auth_method, au.details) as auth_details
FROM auth.end_user eu JOIN auth.auth_user au ON eu.entity_id = au.user_id
WHERE eu.entity_id = $1
)
SELECT es.status_name, eu.display_name, eu.details, eu.email, a.auth_details
FROM auth.end_user eu
JOIN auth.entity_status es ON eu.entity_status_id = es.entity_status_id
CROSS JOIN tmp a WHERE eu.entity_id = $1`
	var p Profile
	err := self.db.QueryRow(ctx, sql, id).Scan(&p.UserStatus, &p.DisplayName, &p.Details, &p.Email, &p.AuthDetails)
	if err != nil {
		return nil, err
	}
	return &p, nil
}

func (self *AuthDbImpl) incFailCount(ctx context.Context, id int64) {
	sql := `UPDATE auth.end_user SET fail_count = fail_count + 1,
last_updated = current_timestamp, last_updated_by = session_user
WHERE entity_id = $1`
	_, err := self.db.Exec(ctx, sql, id)
	if err != nil {
		log.Error().Msgf("failed to increment fail count: %s", err.Error())
	}
}

func (self *AuthDbImpl) Logout(ctx context.Context, p JWTPayload) (bool, error) {
	sql := `DELETE FROM auth.auth_session s
WHERE s.entity_id = $1
AND s.session_key = $2
RETURNING auth_session_id`
	var sessionID int64
	err := self.db.QueryRow(ctx, sql, p.GetID(), p.GetSession()).Scan(&sessionID)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	} else if err != nil {
		return false, err
	}
	return true, nil
}

func (self *AuthDbImpl) IsActiveSession(ctx context.Context, p JWTPayload) (bool, error) {
	sql := `SELECT true FROM auth.auth_session s
WHERE s.entity_id = $1
AND s.session_key = $2
AND s.expiration_ts > current_timestamp`
	var ret bool
	err := self.db.QueryRow(ctx, sql, p.GetID(), p.GetSession()).Scan(&ret)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	} else if err != nil {
		return false, err
	}
	return true, nil
}

func (self *AuthDbImpl) CleanAuthSessions(ctx context.Context) error {
	_, err := self.db.Exec(ctx,
		"DELETE FROM auth.auth_session WHERE expiration_ts < current_timestamp")
	return err
}

func (self *AuthDbImpl) IsLoggedIn(handler http.HandlerFunc) http.HandlerFunc {
	return self.IsValidJWT(func(w http.ResponseWriter, r *http.Request) {
		payload := r.Context().Value(RequestAuthKey).(JWTPayload)
		isActive, err := self.IsActiveSession(r.Context(), payload)
		if err != nil {
			ez.InternalServerErrorHandler(w, r, err)
			return
		} else if !isActive {
			ez.AccessDeniedHandler(w, r, errors.New("session expired"))
			return
		}
		handler.ServeHTTP(w, r)
	})
}

type PhoneCode struct {
	Phone string `json:"phone,omitempty"`
	Code  string `json:"code,omitempty"`
}

func (self *PhoneCode) GetPhone() (string, error) {
	phone := self.Phone
	phone = strings.ReplaceAll(phone, "-", "")
	phone = strings.ReplaceAll(phone, "(", "")
	phone = strings.ReplaceAll(phone, ")", "")
	phone = strings.ReplaceAll(phone, "+", "")
	if _, err := strconv.ParseInt(phone, 10, 64); err != nil {
		return "", err
	}
	if len(phone) < 9 {
		return "", errors.New("phone number too small")
	}
	return phone, nil
}

func (self *AuthDbImpl) CreatePhoneCode(ctx context.Context, phone, ipAddress string) (string, error) {
	sql := `SELECT coalesce(sum(fail_count), 0)
FROM auth.auth_code WHERE auth_method = 'phone' AND ip_address = $1`
	var count int
	err := self.db.QueryRow(ctx, sql, ipAddress).Scan(&count)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return "", err
	}
	if count > maxFailCount {
		return "", errors.New("too many failed attempts")
	}
	sql = `INSERT INTO auth.auth_code (auth_method, auth_id, code, expiration_ts, ip_address)
VALUES ('phone', $1, $2, $3, $4) ON CONFLICT (auth_method, auth_id) DO UPDATE
SET code = $2, expiration_ts = $3, ip_address = $4, last_updated = current_timestamp`
	code := ez.RandIntSeq(6)
	_, err = self.db.Exec(ctx, sql, phone, HashPassword(code), time.Now().Add(time.Minute*5), ipAddress)
	if err != nil {
		return "", err
	}
	return code, nil
}

func (self *AuthDbImpl) CheckPhoneCode(ctx context.Context, pa *PhoneCode) (JWTPayload, error) {
	phone, err := pa.GetPhone()
	if err != nil {
		return nil, err
	}
	sql := `SELECT code, expiration_ts FROM auth.auth_code
WHERE auth_method = 'phone' AND auth_id = $1`
	var hashedCode string
	var expirationTs time.Time
	err = self.db.QueryRow(ctx, sql, phone).Scan(&hashedCode, &expirationTs)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errors.New("invalid phone/code")
	} else if err != nil {
		return nil, err
	} else if expirationTs.Before(time.Now()) || !CheckPassword(hashedCode, pa.Code) {
		return nil, errors.New("invalid code")
	}
	sql = `SELECT eu.email FROM auth.end_user eu JOIN auth.auth_user au ON eu.entity_id = au.user_id
JOIN auth.entity_status es ON eu.entity_status_id = es.entity_status_id
WHERE au.auth_method = 'phone' AND au.hashed_validation = $1 AND es.status_name = $2`
	var email string
	err = self.db.QueryRow(ctx, sql, phone, string(UserStatusVerified)).Scan(&email)
	if errors.Is(err, pgx.ErrNoRows) {
		email = phone + "@phone"
		u := &AuthUser{
			EntityType:       UserEntityType,
			EntityUUID:       uuid.NewV5(uuid.Nil, ez.RandSeq(64)),
			EntityStatus:     UserStatusVerified,
			Email:            email,
			AuthMethod:       "phone",
			HashedValidation: phone,
		}
		return self.UpsertUser(ctx, u, true)
	} else if err != nil {
		return nil, err
	}
	return self.CreatePayload(ctx, email)
}
