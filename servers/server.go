/*
Copyright © 2022 THINKINGATOMS LLC <atom@thinkingatoms.com>
*/

package servers

import (
	"context"
	"encoding/json"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/render"
	"github.com/gofrs/uuid"
	"github.com/gorilla/handlers"
	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/hlog"
	"github.com/rs/zerolog/log"
	"golang.org/x/sync/errgroup"
	"math/rand"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"thinkingatoms.com/apibase/ez"
	"thinkingatoms.com/apibase/models"
	"time"
)

type Server struct {
	Router    *chi.Mux
	setups    []func(ctx context.Context) error
	teardowns []func() error
	db        models.DbConn
	cache     *models.TenureCache

	Name      string    `json:"name"`
	Seed      string    `json:"seed"`
	Port      int       `json:"port"`
	Public    string    `json:"public"`
	DbURL     string    `json:"db_url"`
	Secret    string    `json:"secret"`
	Namespace uuid.UUID `json:"namespace,omitempty"`

	secret []byte
	config map[string]any
}

func SetupRouter() *chi.Mux {
	_log := zerolog.New(os.Stdout).With().
		Timestamp().
		Logger()

	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(hlog.NewHandler(_log))
	r.Use(hlog.RequestIDHandler("request_id", "x-request-id"))
	r.Use(hlog.MethodHandler("method"))
	r.Use(hlog.URLHandler("url"))
	r.Use(hlog.RemoteAddrHandler("remote_ip"))
	r.Use(hlog.AccessHandler(func(r *http.Request, status, size int, duration time.Duration) {
		hlog.FromRequest(r).Info().
			Int("status", status).
			Int("size", size).
			Dur("duration", duration).
			Msg("HTTP request")
	}))

	r.Use(handlers.HTTPMethodOverrideHandler)
	r.Use(middleware.Recoverer)
	return r
}

func NewServer() *Server {
	return &Server{
		Router:    SetupRouter(),
		setups:    make([]func(ctx context.Context) error, 0),
		teardowns: make([]func() error, 0),
	}
}

func (self *Server) GetSecret() []byte {
	return self.secret
}

func (self *Server) GetDb() models.DbConn {
	return self.db
}

func (self *Server) GetCache() *models.TenureCache {
	return self.cache
}

func (self *Server) LoadConfig(configPaths *[]string) {
	self.config = ez.ReturnOrPanic(models.DefaultEnvironment().GetConfig(*configPaths))
	ez.PanicIfErr(json.Unmarshal(ez.ReturnOrPanic(json.Marshal(self.config)), self))
	if self.Seed == "" {
		rand.Seed(time.Now().UnixNano())
	} else {
		rand.Seed(int64(ez.ReturnOrPanic(strconv.Atoi(self.Seed))))
	}
	self.Namespace = uuid.NewV5(uuid.Nil, self.Name)
	self.Secret, self.secret = "", []byte(self.Secret)
	ctx := context.Background()
	if self.DbURL != "" {
		self.db = ez.ReturnOrPanic(pgxpool.Connect(ctx, self.DbURL))
	}
	self.Router.Use(render.SetContentType(render.ContentTypeJSON))
	self.Router.Use(middleware.Heartbeat("/health"))
	if self.HasSubConfig("cache") {
		self.cache = models.BuildTenureCache(ctx, self.GetSubConfig("cache"))
		self.Router.Route("/cache", func(r chi.Router) {
			r.Get("/", func(w http.ResponseWriter, r *http.Request) {
				ez.WriteObjectAsJSON(w, r, self.cache.Info())
			})
			r.Get("/clear/{tenure}", func(w http.ResponseWriter, r *http.Request) {
				tenure := chi.URLParam(r, "tenure")
				switch strings.ToLower(tenure) {
				case "all":
					self.cache.ClearAll()
				case "short":
					self.cache.Clear(models.TenureShort)
				case "medium":
					self.cache.Clear(models.TenureMedium)
				case "long":
					self.cache.Clear(models.TenureLong)
				case "forever":
					self.cache.Clear(models.TenureForever)
				}
			})
		})
	}
}

func (self *Server) HasSubConfig(key string) bool {
	_, ok := self.config[key]
	if !ok {
		return false
	}
	switch self.config[key].(type) {
	case map[string]any:
		return true
	default:
		return false
	}
}

func (self *Server) GetSubConfig(key string) map[string]any {
	return self.config[key].(map[string]any)
}

func (self *Server) AddSetup(f func(ctx context.Context) error) {
	if f == nil {
		return
	}
	self.setups = append(self.setups, f)
}

func (self *Server) AddTeardown(f func() error) {
	if f == nil {
		return
	}
	self.teardowns = append(self.teardowns, f)
}

func (self *Server) Serve() {
	if self.Port == 0 {
		panic("no port specified")
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	srv := &http.Server{
		Addr:    ":" + strconv.Itoa(self.Port),
		Handler: self.Router,
	}

	g, gCtx := errgroup.WithContext(ctx)
	g.Go(func() error {
		return srv.ListenAndServe()
	})
	g.Go(func() error {
		<-gCtx.Done()
		_ = srv.Shutdown(context.Background())
		return nil
	})
	for _, setup := range self.setups {
		g.Go(func() error {
			return setup(gCtx)
		})
	}
	for _, teardown := range self.teardowns {
		g.Go(func() error {
			<-gCtx.Done()
			return teardown()
		})
	}

	log.Info().Msgf("############# web service started at %d / %s #############", self.Port, self.Public)
	if err := g.Wait(); err != nil {
		log.Fatal().Err(err).Msgf("web service shutdown failed: %s", err)
	}
	log.Info().Msg("############# web service stopped #############")
}
