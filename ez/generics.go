/*
Copyright © 2022 THINKINGATOMS LLC <atom@thinkingatoms.com>
*/

package ez

import (
	"encoding/json"
	"github.com/rs/zerolog/log"
	"net/http"
)

//func Chain[A any, B any](f func(A) (B, error)) func(A, error) (B, error) {
//	return func(a A, err error) (B, error) {
//		if err != nil {
//			return nil, err
//		}
//		return f(a)
//	}
//}
//
//func Chain2[A any, B any, C any](g func(*B) (*C, error), f func(*A) (*B, error)) func(A, error) (*C, error) {
//	return func(a A, err error) (*C, error) {
//		if err != nil {
//			return nil, err
//		}
//		b, berr := f(&a)
//		if berr != nil {
//			return nil, berr
//		}
//		return g(b)
//	}
//}

//goland:noinspection GoUnusedExportedFunction
func ReturnOrPanic[K any](k K, err error) K {
	if err != nil {
		panic(err)
	}
	return k
}

//goland:noinspection GoUnusedExportedFunction
func ReturnOrLog[K any](k K, err error) K {
	if err != nil {
		log.Fatal().Err(err).Msg(err.Error())
	}
	return k
}

func PanicIfErr(err error) {
	if err != nil {
		panic(err)
	}
}

func MapToObject(m map[string]any, o any) error {
	marshal, err := json.Marshal(m)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(marshal, o); err != nil {
		return err
	}
	return nil
}

func DoOr500[K any](w http.ResponseWriter, r *http.Request,
	handler func(w http.ResponseWriter, r *http.Request, k K),
) func(k K, err error) {
	return func(k K, err error) {
		if err != nil {
			InternalServerErrorHandler(w, r, err)
			return
		}
		handler(w, r, k)
	}
}

func DoOr401[K any](w http.ResponseWriter, r *http.Request,
	handler func(w http.ResponseWriter, r *http.Request, k K),
) func(k K, err error) {
	return func(k K, err error) {
		if err != nil {
			AccessDeniedHandler(w, r, err)
			return
		}
		handler(w, r, k)
	}
}
