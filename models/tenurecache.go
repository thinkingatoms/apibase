package models

import (
	"container/heap"
	"context"
	"encoding/json"
	"runtime"
	"sync"
	"sync/atomic"
	"thinkingatoms.com/apibase/ez"
	"time"
)

type CacheItem struct {
	Object     any
	Expiration int64
}

const (
	NoCacheExpiration       time.Duration = -1
	DefaultLongExpiration                 = 24 * time.Hour
	DefaultMediumExpiration               = time.Hour
	DefaultShortExpiration                = time.Second * 15
	DefaultCleanInterval                  = time.Minute
)

func (item CacheItem) IsExpired() bool {
	if item.Expiration == 0 {
		return false
	}
	return time.Now().UnixNano() > item.Expiration
}

type Cache struct {
	*cache
	// If this is confusing, see the comment at the bottom of New()
}

type cache struct {
	maxSize          int
	evictSize        int
	expireAfterRead  time.Duration
	expireAfterWrite time.Duration
	items            map[string]CacheItem
	mu               sync.RWMutex
	ih               *keyHeap
	ihKeys           map[string]bool
	onEvicted        func(string, any)
	janitor          *janitor
	hit              int64
	miss             int64
}

func (c *cache) Set(k string, x any) {
	// "Inlining" of set
	var e int64
	var ke *keyAndExpiration
	if c.expireAfterWrite == NoCacheExpiration {
		if c.maxSize == 0 {
			e = 0
		} else {
			e = time.Now().UnixNano()
			ke = &keyAndExpiration{k, e}
		}
	} else {
		e = time.Now().Add(c.expireAfterWrite).UnixNano()
		ke = &keyAndExpiration{k, e}
	}
	c.mu.Lock()
	if c.maxSize > 0 && c.maxSize <= len(c.items) {
		c.evict(len(c.items) - c.maxSize + c.evictSize)
	}
	if e != 0 {
		if _, ok := c.ihKeys[k]; !ok {
			heap.Push(c.ih, ke)
			c.ihKeys[k] = true
		}
	}
	c.items[k] = CacheItem{Object: x, Expiration: e}
	c.mu.Unlock()
}

func (c *cache) evict(num int) {
	var evictedItems []keyAndValue
	for num > 0 && len(c.items) > 0 {
		// "Inlining" of expired
		ke := heap.Pop(c.ih).(*keyAndExpiration)
		delete(c.ihKeys, ke.Key)
		if ci, ok := c.items[ke.Key]; ok {
			if ci.Expiration == ke.Expiration {
				ov, evicted := c.delete(ke.Key)
				if evicted {
					evictedItems = append(evictedItems, keyAndValue{ke.Key, ov})
				}
				num--
			} else {
				heap.Push(c.ih, &keyAndExpiration{ke.Key, ci.Expiration})
				c.ihKeys[ke.Key] = true
			}
		}
	}
	c.mu.Unlock()
	for _, v := range evictedItems {
		c.onEvicted(v.key, v.value)
	}
}

func (c *cache) Get(k string) (any, bool) {
	var e int64
	if c.expireAfterRead == NoCacheExpiration {
		if c.maxSize == 0 {
			e = 0
		} else {
			e = time.Now().UnixNano()
		}
	} else {
		e = time.Now().Add(c.expireAfterRead).UnixNano()
	}
	now := time.Now().UnixNano()
	c.mu.RLock()
	// "Inlining" of get and Expired
	item, found := c.items[k]
	if !found {
		c.mu.RUnlock()
		atomic.AddInt64(&c.miss, 1)
		return nil, false
	}
	if item.Expiration > 0 {
		if now >= item.Expiration {
			c.mu.RUnlock()
			atomic.AddInt64(&c.miss, 1)
			return nil, false
		}
	}
	c.mu.RUnlock()
	if e > 0 && (item.Expiration == 0 || item.Expiration < e) {
		c.mu.Lock()
		if item.Expiration < e {
			item.Expiration = e
			if _, ok := c.ihKeys[k]; !ok {
				heap.Push(c.ih, &keyAndExpiration{k, e})
				c.ihKeys[k] = true
			}
		}
		c.mu.Unlock()
	}
	atomic.AddInt64(&c.hit, 1)
	return item.Object, true
}

// Delete an item from the cache. Does nothing if the key is not in the cache.
func (c *cache) Delete(k string) {
	c.mu.Lock()
	v, evicted := c.delete(k)
	c.mu.Unlock()
	if evicted {
		c.onEvicted(k, v)
	}
}

type keyAndValue struct {
	key   string
	value any
}

func (c *cache) DeleteExpired() {
	var evictedItems []keyAndValue
	now := time.Now().UnixNano()
	c.mu.Lock()
	for len(*c.ih) > 0 && now >= (*c.ih)[0].Expiration {
		// "Inlining" of expired
		ke := heap.Pop(c.ih).(*keyAndExpiration)
		delete(c.ihKeys, ke.Key)
		if ci, ok := c.items[ke.Key]; ok {
			if now >= ci.Expiration {
				ov, evicted := c.delete(ke.Key)
				if evicted {
					evictedItems = append(evictedItems, keyAndValue{ke.Key, ov})
				}
			} else {
				heap.Push(c.ih, &keyAndExpiration{ke.Key, ci.Expiration})
				c.ihKeys[ke.Key] = true
			}
		}
	}
	c.mu.Unlock()
	for _, v := range evictedItems {
		c.onEvicted(v.key, v.value)
	}
}

func (c *cache) delete(k string) (any, bool) {
	if c.onEvicted != nil {
		if v, found := c.items[k]; found {
			delete(c.items, k)
			delete(c.ihKeys, k)
			return v.Object, true
		}
	}
	delete(c.items, k)
	delete(c.ihKeys, k)
	return nil, false
}

func (c *cache) OnEvicted(f func(string, any)) {
	c.mu.Lock()
	c.onEvicted = f
	c.mu.Unlock()
}

func (c *cache) Items() map[string]any {
	c.mu.RLock()
	defer c.mu.RUnlock()
	m := make(map[string]any, len(c.items))
	now := time.Now().UnixNano()
	for k, v := range c.items {
		// "Inlining" of Expired
		if v.Expiration > 0 {
			if now >= v.Expiration {
				continue
			}
		}
		m[k] = v.Object
	}
	return m
}

func (c *cache) Count() int {
	c.mu.RLock()
	n := len(c.items)
	c.mu.RUnlock()
	return n
}

func (c *cache) Clear() {
	c.mu.Lock()
	items := c.items
	c.items = make(map[string]CacheItem)
	c.ihKeys = make(map[string]bool)
	c.ih = &keyHeap{}
	if c.onEvicted != nil {
		for k, v := range items {
			c.onEvicted(k, v.Object)
		}
	}
	c.hit = 0
	c.miss = 0
	c.mu.Unlock()
}

func (c *cache) Info() map[string]int64 {
	return map[string]int64{
		"hit":   atomic.LoadInt64(&c.hit),
		"miss":  atomic.LoadInt64(&c.miss),
		"count": int64(len(c.items)),
	}
}

type keyAndExpiration struct {
	Key        string
	Expiration int64
}

type keyHeap []*keyAndExpiration

func (ih keyHeap) Len() int {
	return len(ih)
}

func (ih keyHeap) Less(i, j int) bool {
	return ih[i].Expiration < ih[j].Expiration
}

func (ih keyHeap) Swap(i, j int) {
	ih[i], ih[j] = ih[j], ih[i]
}

func (ih *keyHeap) Push(x any) {
	*ih = append(*ih, x.(*keyAndExpiration))
}

func (ih *keyHeap) Pop() any {
	old := *ih
	n := len(old)
	x := old[n-1]
	*ih = old[0 : n-1]
	return x
}

type janitor struct {
	interval time.Duration
	stop     chan bool
}

func (j *janitor) Run(ctx context.Context, c *cache) {
	ticker := time.NewTicker(j.interval)
	for {
		select {
		case <-ticker.C:
			c.DeleteExpired()
		case <-ctx.Done():
			return
		case <-j.stop:
			return
		}
	}
}

func stopJanitor(c *Cache) {
	c.janitor.stop <- true
}

type Tenure int

const (
	_ Tenure = iota
	TenureShort
	TenureMedium
	TenureLong
	TenureForever
	TenureNever
)

type TenureCache struct {
	Long    *Cache
	Medium  *Cache
	Short   *Cache
	Forever *Cache
}

func (c *TenureCache) Get(tenure Tenure, k string) (any, bool) {
	switch tenure {
	case TenureShort:
		return c.Short.Get(k)
	case TenureMedium:
		return c.Medium.Get(k)
	case TenureLong:
		return c.Long.Get(k)
	case TenureForever:
		return c.Forever.Get(k)
	case TenureNever:
		return nil, false
	default:
		panic("invalid tenure specified")
	}
}

func (c *TenureCache) Set(tenure Tenure, k string, v any) {
	switch tenure {
	case TenureShort:
		c.Short.Set(k, v)
	case TenureMedium:
		c.Medium.Set(k, v)
	case TenureLong:
		c.Long.Set(k, v)
	case TenureForever:
		c.Forever.Set(k, v)
	case TenureNever:
		panic("TenureNever should be handled outside")
	default:
		panic("invalid tenure specified")
	}
}

func (c *TenureCache) Delete(tenure Tenure, k string) {
	switch tenure {
	case TenureShort:
		c.Short.Delete(k)
	case TenureMedium:
		c.Medium.Delete(k)
	case TenureLong:
		c.Long.Delete(k)
	case TenureForever:
		c.Forever.Delete(k)
	default:
		return
	}
}

func (c *TenureCache) Clear(tenure Tenure) {
	switch tenure {
	case TenureShort:
		c.Short.Clear()
	case TenureMedium:
		c.Medium.Clear()
	case TenureLong:
		c.Long.Clear()
	case TenureForever:
		c.Forever.Clear()
	case TenureNever:
		return
	default:
		return
	}
}

func (c *TenureCache) ClearAll() {
	c.Long.Clear()
	c.Short.Clear()
	c.Medium.Clear()
	c.Forever.Clear()
}

func (c *TenureCache) Info() map[string]map[string]int64 {
	return map[string]map[string]int64{
		"long":    c.Long.Info(),
		"medium":  c.Medium.Info(),
		"short":   c.Short.Info(),
		"forever": c.Forever.Info(),
	}
}

func NewCache(ctx context.Context,
	expireAfterRead, expireAfterWrite, cleanInterval time.Duration,
	maxSize, evictSize int,
) *Cache {
	if cleanInterval == 0 {
		panic("cleanInterval must be positive")
	}
	if maxSize > 0 && evictSize <= 0 {
		evictSize = int(float32(maxSize) * 0.1)
		if evictSize < 1 {
			evictSize = 1
		}
	}
	c := &cache{
		maxSize:          maxSize,
		evictSize:        evictSize,
		expireAfterRead:  expireAfterRead,
		expireAfterWrite: expireAfterWrite,
		items:            make(map[string]CacheItem),
		ih:               &keyHeap{},
		ihKeys:           make(map[string]bool),
		janitor:          &janitor{stop: make(chan bool), interval: cleanInterval},
	}
	ret := &Cache{c}
	if cleanInterval != NoCacheExpiration {
		go c.janitor.Run(ctx, c)
		runtime.SetFinalizer(ret, stopJanitor)
	}
	return ret
}

type tenureCacheConfig struct {
	LongSize      int           `json:"long_size"`
	MediumSize    int           `json:"medium_size"`
	ShortSize     int           `json:"short_size"`
	ForeverSize   int           `json:"forever_size"`
	LongExpiry    time.Duration `json:"long_expiry"`
	MediumExpiry  time.Duration `json:"medium_expiry"`
	ShortExpiry   time.Duration `json:"short_expiry"`
	CleanInterval time.Duration `json:"clean_interval"`
}

func BuildTenureCache(ctx context.Context, config map[string]any) *TenureCache {
	var tc tenureCacheConfig
	ez.PanicIfErr(json.Unmarshal(ez.ReturnOrPanic(json.Marshal(config)), &tc))
	if tc.CleanInterval > 0 {
		tc.CleanInterval *= time.Second
	}
	if tc.LongExpiry > 0 {
		tc.LongExpiry *= time.Second
	}
	if tc.MediumExpiry > 0 {
		tc.MediumExpiry *= time.Second
	}
	if tc.ShortExpiry > 0 {
		tc.ShortExpiry *= time.Second
	}
	return &TenureCache{
		Long:    NewCache(ctx, NoCacheExpiration, tc.LongExpiry, tc.CleanInterval, tc.LongSize, 0),
		Medium:  NewCache(ctx, tc.MediumExpiry, tc.MediumExpiry, tc.CleanInterval, tc.MediumSize, 0),
		Short:   NewCache(ctx, NoCacheExpiration, tc.ShortExpiry, tc.CleanInterval, tc.ShortSize, 0),
		Forever: NewCache(ctx, NoCacheExpiration, NoCacheExpiration, NoCacheExpiration, tc.ForeverSize, 0),
	}
}

func NewTenureCache(ctx context.Context) *TenureCache {
	return BuildTenureCache(ctx, map[string]any{
		"long_size":      1000,
		"medium_size":    1000,
		"short_size":     1000,
		"forever_size":   1000,
		"long_expiry":    DefaultLongExpiration,
		"medium_expiry":  DefaultMediumExpiration,
		"short_expiry":   DefaultShortExpiration,
		"clean_interval": DefaultCleanInterval,
	})
}

func _() {
	_ = NewTenureCache
}
