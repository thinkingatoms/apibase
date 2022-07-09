/*
Copyright © 2022 THINKINGATOMS LLC <atom@thinkingatoms.com>
*/

package stripesvc

import (
	"github.com/go-chi/chi/v5"
	"github.com/gofrs/uuid"
	"github.com/stripe/stripe-go/v72"
	"github.com/stripe/stripe-go/v72/checkout/session"
	"github.com/stripe/stripe-go/v72/webhook"
	errors "golang.org/x/xerrors"
	"io/ioutil"
	"net/http"
	"thinkingatoms.com/apibase/ez"
	"thinkingatoms.com/apibase/models"
	"thinkingatoms.com/apibase/servers"
)

type stripeService struct {
	name      string
	server    *servers.Server
	namespace uuid.UUID
	db        models.DbConn
	auth      models.Auth

	SecretKey      string `json:"secret_key"`
	PublishableKey string `json:"publishable_key"`
	WebhookSecret  string `json:"webhook_secret"`
	ProductID      string `json:"product_id"`
	PriceID        string `json:"price_id"`
	DbURL          string `json:"db_url"`
}

func CreateStripeService(server *servers.Server, auth models.Auth) (*stripeService, error) {
	db := server.GetDb()
	if db == nil {
		return nil, errors.New("no database connection")
	}

	name := "stripe"
	if !server.HasSubConfig(name) {
		return nil, nil
	}
	s := stripeService{
		name:      name,
		server:    server,
		namespace: uuid.NewV5(server.Namespace, name),
		db:        db,
		auth:      auth,
	}
	ez.PanicIfErr(ez.MapToObject(server.GetSubConfig(name), &s))
	if s.SecretKey == "" || s.PublishableKey == "" {
		return nil, errors.New("missing Stripe keys")
	}
	if s.ProductID == "" || s.PriceID == "" {
		return nil, errors.New("product_id and price_id are required")
	}

	return &s, nil
}

func RegisterStripeService(server *servers.Server, auth models.Auth) error {
	s, err := CreateStripeService(server, auth)
	if err != nil {
		return err
	}
	if s != nil {
		s.EnrichRouter(server.Router)
	}
	return nil
}

func (self *stripeService) EnrichRouter(r *chi.Mux) {
	stripe.Key = self.SecretKey
	r.Post("/stripe/start", self.auth.IsValidJWT(self.createCheckoutHandler))
	r.Get("/stripe/complete", self.completeCheckoutHandler)
	r.Get("/stripe/cancel", self.cancelCheckoutHandler)
	r.Post("/stripe/webhook", self.webhookHandler)
}

func (self *stripeService) createCheckoutHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	payload := ctx.Value(models.RequestAuthKey).(models.JWTPayload)
	id := payload.GetID()
	params := &stripe.CheckoutSessionParams{
		SuccessURL:        stripe.String(self.server.Public + "/stripe/complete?session_id={CHECKOUT_SESSION_ID}"),
		CancelURL:         stripe.String(self.server.Public + "/stripe/cancel?session_id={CHECKOUT_SESSION_ID}"),
		Mode:              stripe.String(string(stripe.CheckoutSessionModeSubscription)),
		ClientReferenceID: &id,
		LineItems: []*stripe.CheckoutSessionLineItemParams{
			{
				Price:    stripe.String(self.PriceID),
				Quantity: stripe.Int64(1),
			},
		},
	}

	s, err := session.New(params)
	if err != nil {
		ez.InternalServerErrorHandler(w, r, err)
		return
	}
	http.Redirect(w, r, s.URL, http.StatusSeeOther)
}

func (self *stripeService) completeCheckoutHandler(w http.ResponseWriter, r *http.Request) {
	sessionID := r.URL.Query().Get("session_id")
	ez.DoOr500(w, r, ez.WriteObjectAsJSON)(session.Get(sessionID, nil))
}

func (self *stripeService) cancelCheckoutHandler(w http.ResponseWriter, r *http.Request) {
	sessionID := r.URL.Query().Get("session_id")
	ez.DoOr500(w, r, ez.WriteObjectAsJSON)(session.Get(sessionID, nil))
}

func (self *stripeService) webhookHandler(w http.ResponseWriter, r *http.Request) {
	b, err := ioutil.ReadAll(r.Body)
	if err != nil {
		ez.BadRequestHandler(w, r, err)
		return
	}

	event, err := webhook.ConstructEvent(b, r.Header.Get("Stripe-Signature"), self.WebhookSecret)
	if err != nil {
		ez.BadRequestHandler(w, r, err)
		return
	}

	if event.Type == "checkout.session.completed" {
		// TODO: save db
	}
}
