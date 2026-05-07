/* SPDX-License-Identifier: MIT */

package turn

import (
	"context"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type TurnCredentials struct {
	Username   string
	Password   string
	ServerAddr string
	ExpiresAt  time.Time
	Link       string
}

type streamCredentialsCache struct {
	creds         TurnCredentials
	mutex         sync.Mutex
	errorCount    atomic.Int32
	lastErrorTime atomic.Int64
}

const (
	credentialLifetime = 10 * time.Minute
	cacheSafetyMargin  = 60 * time.Second
	maxCacheErrors     = 3
	errorWindow        = 10 * time.Second
)

var streamsPerCred = 4

func getCacheID(streamID int) int { return streamID / streamsPerCred }

var credentialsStore = struct {
	mu     sync.RWMutex
	caches map[int]*streamCredentialsCache
}{caches: make(map[int]*streamCredentialsCache)}

func getStreamCache(streamID int) *streamCredentialsCache {
	cacheID := getCacheID(streamID)
	credentialsStore.mu.RLock()
	cache := credentialsStore.caches[cacheID]
	credentialsStore.mu.RUnlock()
	if cache != nil {
		return cache
	}
	credentialsStore.mu.Lock()
	defer credentialsStore.mu.Unlock()
	if cache = credentialsStore.caches[cacheID]; cache != nil {
		return cache
	}
	cache = &streamCredentialsCache{}
	credentialsStore.caches[cacheID] = cache
	return cache
}

func isAuthError(err error) bool {
	errStr := err.Error()
	return strings.Contains(errStr, "401") || strings.Contains(errStr, "Unauthorized") || strings.Contains(errStr, "authentication") || strings.Contains(errStr, "invalid credential") || strings.Contains(errStr, "stale nonce")
}

func handleAuthError(streamID int) bool {
	cache := getStreamCache(streamID)
	now := time.Now().Unix()
	if now-cache.lastErrorTime.Load() > int64(errorWindow.Seconds()) {
		cache.errorCount.Store(0)
	}
	count := cache.errorCount.Add(1)
	cache.lastErrorTime.Store(now)
	if count >= maxCacheErrors {
		cache.invalidate()
		return true
	}
	return false
}

func (c *streamCredentialsCache) invalidate() {
	c.mutex.Lock()
	c.creds = TurnCredentials{}
	c.mutex.Unlock()
	c.errorCount.Store(0)
	c.lastErrorTime.Store(0)
}

var fetchMu sync.Mutex

type fetchFunc func(ctx context.Context, link string) (string, string, string, error)

func getCredsCached(ctx context.Context, link string, streamID int, storeFn fetchFunc) (string, string, string, error) {
	cache := getStreamCache(streamID)
	cache.mutex.Lock()
	defer cache.mutex.Unlock()
	if cache.creds.Link == link && time.Now().Before(cache.creds.ExpiresAt) {
		return cache.creds.Username, cache.creds.Password, cache.creds.ServerAddr, nil
	}
	select {
	case <-ctx.Done():
		return "", "", "", ctx.Err()
	default:
	}
	fetchMu.Lock()
	user, pass, addr, err := storeFn(ctx, link)
	fetchMu.Unlock()
	if err != nil {
		return "", "", "", err
	}
	cache.creds = TurnCredentials{Username: user, Password: pass, ServerAddr: addr, ExpiresAt: time.Now().Add(credentialLifetime - cacheSafetyMargin), Link: link}
	return user, pass, addr, nil
}
