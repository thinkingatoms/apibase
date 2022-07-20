package models

import (
	"github.com/rs/zerolog/log"
	"github.com/thinkingatoms/apibase/ez"
	errors "golang.org/x/xerrors"
	"math"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
)

//goland:noinspection GoSnakeCaseUsage
const APP_NAME_KEY = DEFAULT_ROOT_NAME + "_NAME"

//goland:noinspection GoSnakeCaseUsage
const DEFAULT_APP_NAME string = ""

//goland:noinspection GoSnakeCaseUsage
const ENV_NAME_KEY = DEFAULT_ROOT_NAME + "_ENV_NAME"

//goland:noinspection GoSnakeCaseUsage
const DEFAULT_ENV_NAME string = ""

//goland:noinspection GoSnakeCaseUsage
const ENV_URL_KEY = DEFAULT_ROOT_NAME + "_ENV_ROOT_URL"

//goland:noinspection GoSnakeCaseUsage
const DEFAULT_ENV_URL string = "http://config"

//goland:noinspection GoSnakeCaseUsage
const APP_USER_KEY = DEFAULT_ROOT_NAME + "_USER"

const chainSep = "."

type Environment struct {
	name       string
	httpClient *HTTPClient
	user       *string
}

func (self *Environment) GetUser() string {
	if self.user == nil {
		userName := os.Getenv(APP_USER_KEY)
		if userName == "" {
			v, err := user.Current()
			if err != nil {
				log.Fatal().Msgf("cannot get user Name due to: %s", err.Error())
			}
			userName = v.Name
		}
		self.user = &userName
	}
	return *self.user
}

func (self *Environment) GetConfig(parts []string) (map[string]any, error) {
	/*
			parses a list of configuration parts, and return a cohesive config

		   configuration parts are strings each in the format of
		       [resulting.path.to.key==]path/to/config.json[:::source_key1[,source_key2[,source_key3]]]
		       [resulting.path.to.key=:]value

			    it might look confusing, here are some examples:
			        let's assume we have a config at "my/config.json" that looks like:
			        {"a": 1, "b", 2, "c": {"d": 3, "e": 4}}

			if you specified:
				with input of:
			        my/config.json
			    you will get back the full file, ie:
			        {"a": 1, "b", 2, "c": {"d": 3, "e": 4}}

			if you specified with "==", the left part is the path that you want to store,
		 	the right side of the "==" is the path to config that you want to store

				with input of:
			        f.g==my/config.json
			    you will get back:
			        {"f": {"g": {"a": 1, "b", 2, "c": {"d": 3, "e": 4}}}}

			if you specified with "=", the left part is the path that you want to store,
		 	the right side of the "=" is the literal value that you want to store

				with input of:
			        d.e=1
			    you will get back:
			        {"d": {"e": 1}}

			if you specified "::" with any config path,
			you would only get back the paths specified after the "::":

				with input of:
			        my/config.json::c.d,b
				you will get back:
					{"b", 2, "c": {"d": 3}}

				with input of:
			        f.g==my/config.json::c.d,b
			    you will get back:
					{"f": {"g": {"b", 2, "c": {"d": 3}}}}

			if you specified "=:" with any config path,
			you would only get back the single path specified after the "=:".
			the specified path must point to a map

				NOT VALID:
			        my/config.json=:c.d
				instead of getting back 3, it will error

				with input of:
			        my/config.json=:c
			    you will get back:
			        {"d": 3, "e": 4}

				with input of:
			        f.g==my/config.json=:c
			    you will get back:
			        {"f": {"g": {"d": 3, "e": 4}}}
	*/
	cache := make(map[string]any)
	ret := make(map[string]any)
	var err error
	extracts := make([]string, 0)
	for _, part := range parts {
		var keys []string
		var value any
		var immediateKey string
		path := part
		if before, after, found := strings.Cut(part, "=="); found {
			keys = strings.Split(before, chainSep)
			path = after
		}
		if before, after, found := strings.Cut(part, "=:"); found {
			path = before
			immediateKey = after
		} else if before, after, found := strings.Cut(part, "="); found {
			keys = strings.Split(before, chainSep)
			value, err = self.parseConfigValue(after)
			if err != nil {
				return nil, err
			}
			path = ""
		}
		if path != "" {
			if before, after, found := strings.Cut(path, "::"); found {
				path = before
				extractPrefix := ""
				if len(keys) > 0 {
					extractPrefix = strings.Join(keys, chainSep) + chainSep
				}
				for _, extract := range strings.Split(after, ",") {
					extracts = append(extracts, extractPrefix+extract)
				}
			}
			if v, found := cache[path]; found {
				value = v.(map[string]any)
			} else {
				value, err = self.getConfig(path)
				if err != nil {
					return nil, err
				}
				cache[path] = value
			}
			if immediateKey != "" {
				value, err = self.extractValue(value, strings.Split(immediateKey, chainSep))
				if err != nil {
					return nil, err
				}
			}
		}
		if keys != nil {
			self.insertConfig(keys, value, &ret)
		} else {
			for k, v := range value.(map[string]any) {
				ret[k] = v
			}
		}
	}

	//for k, v := range ret {
	//	log.Debug().Msg("config: " + k + ": " + fmt.Sprintf("%v", v))
	//}

	err = self.substitute(&ret, &ret)
	if len(extracts) > 0 {
		_ret := make(map[string]any)
		for _, extract := range extracts {
			if before, after, found := strings.Cut(extract, ":"); found {
				value, err := self.extractValue(ret, strings.Split(after, chainSep))
				if err != nil {
					return nil, err
				}
				self.insertConfig(strings.Split(before, chainSep), value, &_ret)
			} else {
				value, err := self.extractValue(ret, strings.Split(extract, chainSep))
				if err != nil {
					return nil, err
				}
				for k, v := range value.(map[string]any) {
					_ret[k] = v
				}
			}
		}
		ret = _ret
	}
	return ret, err
}

func (self *Environment) getConfig(path string) (map[string]any, error) {
	uri := filepath.Join(self.name, path)
	return self.httpClient.ToJSON(self.httpClient.Get(uri, nil))
}

func (_ *Environment) parseConfigValue(value string) (any, error) {
	lower := strings.ToLower(value)
	if lower == "none" {
		return nil, nil
	} else if lower == "true" {
		return true, nil
	} else if lower == "false" {
		return false, nil
	} else if v, err := strconv.Atoi(value); err == nil {
		return v, nil
	} else if v, err := strconv.ParseFloat(value, 64); err == nil {
		return v, nil
	} else if value == "nan" {
		return math.NaN(), nil
	}
	return value, nil
}

func (_ *Environment) insertConfig(keys []string, value any, _config *map[string]any) {
	n := len(keys) - 1
	config := *_config
	for i := 0; i < n; i++ {
		key := keys[i]
		v, found := config[key]
		if !found {
			tmp := make(map[string]any)
			config[key] = tmp
			config = tmp
		} else {
			config = v.(map[string]any)
		}
	}
	config[keys[n]] = value
}

func (self *Environment) substitute(_x *map[string]any, _root *map[string]any) error {
	x := *_x
	root := *_root

	isSub := func(key string) bool {
		start, end := strings.Index(key, "%("), strings.Index(key, ")%")
		return start > -1 && end > start
	}
	getSub := func(key string) (any, error) {
		var ret any
		var err error
		if strings.HasPrefix(key, "env:") {
			ret = os.Getenv(key[4:])
		} else {
			ret, err = self.extractValue(root, strings.Split(key, "."))
			if err != nil {
				return "", err
			}
			switch ret.(type) {
			case string:
				if isSub(ret.(string)) {
					return nil, errors.New("cannot chain substitution: " + key)
				}
			default:
				return ret, nil
			}
		}
		return ret, nil
	}
	sub := func(key string) (any, error) {
		for isSub(key) {
			start, end := strings.Index(key, "%("), strings.Index(key, ")%")
			k := key[start+2 : end]
			v, err := getSub(k)
			if err != nil {
				return "", err
			}
			if start == 0 && end == len(key)-2 {
				return v, nil
			}
			switch v.(type) {
			case string:
				key = key[:start] + v.(string) + key[end+2:]
			default:
				return nil, errors.New("invalid substitution: " + key)
			}
		}
		return key, nil
	}

	var err error
	keyReplacements := make([]string, 0)
	for k := range x {
		if isSub(k) {
			keyReplacements = append(keyReplacements, k)
		}
	}
	for _, key := range keyReplacements {
		tmp, ok := x[key]
		if !ok {
			return errors.New("key not found: " + key)
		}
		replacement, err := sub(key)
		if err != nil {
			return err
		}
		switch replacement.(type) {
		case string:
			x[replacement.(string)] = tmp
		default:
			return errors.New("invalid key substitution: " + key)
		}
		delete(x, key)
	}
	for k, v := range x {
		switch v.(type) {
		case string:
			if isSub(v.(string)) {
				x[k], err = sub(v.(string))
				if err != nil {
					return err
				}
			}
		default:
			continue
		}
	}
	for _, v := range x {
		switch v.(type) {
		case map[string]any:
			_v := v.(map[string]any)
			err = self.substitute(&_v, &root)
			if err != nil {
				return err
			}
		case []any:
			tmp := v.([]any)
			for i, _v := range tmp {
				_tmp := map[string]any{"": _v}
				err := self.substitute(&_tmp, &root)
				if err != nil {
					return err
				}
				tmp[i] = _tmp[""]
			}
		default:
			continue
		}
	}
	return nil
}

func (_ *Environment) extractValue(v any, keys []string) (any, error) {
	ret := v
	for _, key := range keys {
		tmp, found := ret.(map[string]any)[key]
		if !found {
			return nil, errors.New("key not found: " + strings.Join(keys, "."))
		}
		ret = tmp
	}
	return ret, nil
}

func NewEnvironment(name, env, rootURL string) *Environment {
	httpClient := NewHTTPClient(rootURL, 20, 10, 10)
	version := ez.ReturnOrPanic(httpClient.ToJSON(httpClient.Get("VERSION.json", nil)))
	if version["name"].(string) != name {
		panic("unexpected name " + name + " vs version name " + version["name"].(string))
	}
	if version["env"].(string) != env {
		panic("unexpected env " + env + " vs version name " + version["env"].(string))
	}
	return &Environment{
		name:       env,
		httpClient: httpClient,
	}
}

var defaultEnvironment *Environment

func DefaultEnvironment() *Environment {
	if defaultEnvironment == nil {
		name := os.Getenv(APP_NAME_KEY)
		if name == "" {
			name = DEFAULT_APP_NAME
		}
		env := os.Getenv(ENV_NAME_KEY)
		if env == "" {
			env = DEFAULT_ENV_NAME
		}
		rootURL := os.Getenv(ENV_URL_KEY)
		if rootURL == "" {
			rootURL = DEFAULT_ENV_URL
		}
		defaultEnvironment = NewEnvironment(name, env, rootURL)
	}
	return defaultEnvironment
}

func _() {
	_ = DefaultEnvironment
}
