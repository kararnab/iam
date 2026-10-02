// Package redisstore implements session.Store and ratelimit.Limiter on
// Redis (github.com/redis/go-redis/v9).
//
// Every key shares the "{iam}" hash tag, so all keys live in one slot and
// the Lua scripts stay atomic on Redis Cluster too. Session keys expire with
// the session's absolute expiry.
package redisstore

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/kararnab/iam/v2/session"
)

// Sessions implements session.Store.
//
// Layout (prefix defaults to "{iam}:"):
//
//	<p>sess:<id>       JSON session record
//	<p>tok:<hash>      "<id> <rotatedAtUnixNano>" (0 for the current token)
//	<p>toks:<id>       set of the session's token hashes
//	<p>subj:<subject>  set of the subject's session IDs
type Sessions struct {
	rdb    redis.UniversalClient
	prefix string
}

var _ session.Store = (*Sessions)(nil)

// NewSessions returns a session store. prefix namespaces the keys; it must
// contain a hash tag such as "{iam}:" for Redis Cluster. Empty means "{iam}:".
func NewSessions(rdb redis.UniversalClient, prefix string) *Sessions {
	if prefix == "" {
		prefix = "{iam}:"
	}
	return &Sessions{rdb: rdb, prefix: prefix}
}

type record struct {
	ID         string            `json:"id"`
	SubjectID  string            `json:"subject_id"`
	Mode       session.Mode      `json:"mode"`
	TokenHash  string            `json:"token_hash"` // hex
	CreatedAt  time.Time         `json:"created_at"`
	LastUsedAt time.Time         `json:"last_used_at"`
	ExpiresAt  time.Time         `json:"expires_at"`
	Attrs      map[string]string `json:"attrs,omitempty"`
}

func toRecord(s *session.Session) record {
	return record{
		ID: s.ID, SubjectID: s.SubjectID, Mode: s.Mode, TokenHash: hex.EncodeToString(s.TokenHash),
		CreatedAt: s.CreatedAt, LastUsedAt: s.LastUsedAt, ExpiresAt: s.ExpiresAt, Attrs: s.Attrs,
	}
}

func (r record) session() (*session.Session, error) {
	h, err := hex.DecodeString(r.TokenHash)
	if err != nil {
		return nil, err
	}
	return &session.Session{
		ID: r.ID, SubjectID: r.SubjectID, Mode: r.Mode, TokenHash: h,
		CreatedAt: r.CreatedAt, LastUsedAt: r.LastUsedAt, ExpiresAt: r.ExpiresAt, Attrs: r.Attrs,
	}, nil
}

func (m *Sessions) sessKey(id string) string   { return m.prefix + "sess:" + id }
func (m *Sessions) tokKey(h []byte) string     { return m.prefix + "tok:" + hex.EncodeToString(h) }
func (m *Sessions) toksKey(id string) string   { return m.prefix + "toks:" + id }
func (m *Sessions) subjKey(subj string) string { return m.prefix + "subj:" + subj }

// ttl keeps keys until the absolute expiry (at least one second).
func ttl(expires time.Time) time.Duration {
	return max(time.Until(expires), time.Second)
}

var createScript = redis.NewScript(`
-- KEYS: sess, tok, toks, subj   ARGV: record, id, tokHex, ttlMillis
if redis.call('EXISTS', KEYS[1]) == 1 or redis.call('EXISTS', KEYS[2]) == 1 then
  return redis.error_reply('exists')
end
redis.call('SET', KEYS[1], ARGV[1], 'PX', ARGV[4])
redis.call('SET', KEYS[2], ARGV[2] .. ' 0', 'PX', ARGV[4])
redis.call('SADD', KEYS[3], ARGV[3])
redis.call('PEXPIRE', KEYS[3], ARGV[4])
redis.call('SADD', KEYS[4], ARGV[2])
return 1
`)

// Create implements session.Store.
func (m *Sessions) Create(ctx context.Context, s *session.Session) error {
	b, err := json.Marshal(toRecord(s))
	if err != nil {
		return err
	}
	return createScript.Run(ctx, m.rdb,
		[]string{m.sessKey(s.ID), m.tokKey(s.TokenHash), m.toksKey(s.ID), m.subjKey(s.SubjectID)},
		b, s.ID, hex.EncodeToString(s.TokenHash), ttl(s.ExpiresAt).Milliseconds()).Err()
}

func (m *Sessions) get(ctx context.Context, id string) (*session.Session, error) {
	b, err := m.rdb.Get(ctx, m.sessKey(id)).Bytes()
	if errors.Is(err, redis.Nil) {
		return nil, session.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	var r record
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, err
	}
	return r.session()
}

// Get implements session.Store.
func (m *Sessions) Get(ctx context.Context, id string) (*session.Session, error) {
	return m.get(ctx, id)
}

// GetByTokenHash implements session.Store.
func (m *Sessions) GetByTokenHash(ctx context.Context, hash []byte) (*session.Session, session.TokenState, error) {
	v, err := m.rdb.Get(ctx, m.tokKey(hash)).Result()
	if errors.Is(err, redis.Nil) {
		return nil, session.TokenState{}, session.ErrNotFound
	}
	if err != nil {
		return nil, session.TokenState{}, err
	}
	id, nanos, ok := strings.Cut(v, " ")
	if !ok {
		return nil, session.TokenState{}, errors.New("redisstore: corrupt token entry")
	}
	s, err := m.get(ctx, id)
	if err != nil {
		return nil, session.TokenState{}, err
	}
	var state session.TokenState
	if n, _ := strconv.ParseInt(nanos, 10, 64); n != 0 {
		state.RotatedAt = time.Unix(0, n)
	}
	return s, state, nil
}

var rotateScript = redis.NewScript(`
-- KEYS: sess, oldTok, newTok, toks   ARGV: oldHex, newHex, atNanos, lastUsedJSON, id
local raw = redis.call('GET', KEYS[1])
if not raw then return redis.error_reply('notfound') end
local rec = cjson.decode(raw)
if rec['token_hash'] ~= ARGV[1] then return redis.error_reply('conflict') end
if redis.call('EXISTS', KEYS[3]) == 1 then return redis.error_reply('exists') end
local ttl = redis.call('PTTL', KEYS[1])
if ttl < 1 then ttl = 1000 end
rec['token_hash'] = ARGV[2]
rec['last_used_at'] = cjson.decode(ARGV[4])
redis.call('SET', KEYS[1], cjson.encode(rec), 'PX', ttl)
redis.call('SET', KEYS[2], ARGV[5] .. ' ' .. ARGV[3], 'PX', ttl)
redis.call('SET', KEYS[3], ARGV[5] .. ' 0', 'PX', ttl)
redis.call('SADD', KEYS[4], ARGV[2])
return 1
`)

func scriptErr(err error) error {
	if err == nil {
		return nil
	}
	// Redis may prefix script errors with "ERR ".
	switch strings.TrimPrefix(err.Error(), "ERR ") {
	case "notfound":
		return session.ErrNotFound
	case "conflict":
		return session.ErrConflict
	}
	return err
}

// Rotate implements session.Store atomically in a Lua script.
func (m *Sessions) Rotate(ctx context.Context, id string, oldHash, newHash []byte, at time.Time) error {
	at = at.UTC()
	lastUsed, _ := json.Marshal(at)
	return scriptErr(rotateScript.Run(ctx, m.rdb,
		[]string{m.sessKey(id), m.tokKey(oldHash), m.tokKey(newHash), m.toksKey(id)},
		hex.EncodeToString(oldHash), hex.EncodeToString(newHash), strconv.FormatInt(at.UnixNano(), 10), lastUsed, id).Err())
}

var touchScript = redis.NewScript(`
-- KEYS: sess   ARGV: lastUsedJSON
local raw = redis.call('GET', KEYS[1])
if not raw then return redis.error_reply('notfound') end
local rec = cjson.decode(raw)
rec['last_used_at'] = cjson.decode(ARGV[1])
redis.call('SET', KEYS[1], cjson.encode(rec), 'KEEPTTL')
return 1
`)

// Touch implements session.Store.
func (m *Sessions) Touch(ctx context.Context, id string, at time.Time) error {
	lastUsed, _ := json.Marshal(at.UTC())
	return scriptErr(touchScript.Run(ctx, m.rdb, []string{m.sessKey(id)}, lastUsed).Err())
}

var deleteScript = redis.NewScript(`
-- KEYS: sess, toks   ARGV: tokPrefix, subjPrefix
local raw = redis.call('GET', KEYS[1])
for _, h in ipairs(redis.call('SMEMBERS', KEYS[2])) do
  redis.call('DEL', ARGV[1] .. h)
end
redis.call('DEL', KEYS[2])
if raw then
  local rec = cjson.decode(raw)
  redis.call('SREM', ARGV[2] .. rec['subject_id'], rec['id'])
  redis.call('DEL', KEYS[1])
  return 1
end
return 0
`)

// Delete implements session.Store.
func (m *Sessions) Delete(ctx context.Context, id string) error {
	_, err := m.delete(ctx, id)
	return err
}

func (m *Sessions) delete(ctx context.Context, id string) (bool, error) {
	n, err := deleteScript.Run(ctx, m.rdb, []string{m.sessKey(id), m.toksKey(id)}, m.prefix+"tok:", m.prefix+"subj:").Int()
	return n == 1, err
}

// ListBySubject implements session.Store. Expired session IDs are pruned
// from the subject's index as a side effect.
func (m *Sessions) ListBySubject(ctx context.Context, subjectID string) ([]*session.Session, error) {
	ids, err := m.rdb.SMembers(ctx, m.subjKey(subjectID)).Result()
	if err != nil {
		return nil, err
	}
	var out []*session.Session
	for _, id := range ids {
		s, err := m.get(ctx, id)
		if errors.Is(err, session.ErrNotFound) {
			m.rdb.SRem(ctx, m.subjKey(subjectID), id)
			continue
		}
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, nil
}

// DeleteBySubject implements session.Store.
func (m *Sessions) DeleteBySubject(ctx context.Context, subjectID, exceptID string) (int, error) {
	ids, err := m.rdb.SMembers(ctx, m.subjKey(subjectID)).Result()
	if err != nil {
		return 0, err
	}
	n := 0
	for _, id := range ids {
		if id == exceptID {
			continue
		}
		deleted, err := m.delete(ctx, id)
		if err != nil {
			return n, err
		}
		if deleted {
			n++
		} else {
			m.rdb.SRem(ctx, m.subjKey(subjectID), id)
		}
	}
	return n, nil
}
