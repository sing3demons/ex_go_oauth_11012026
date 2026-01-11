package jwks

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"time"

	"github.com/sing3demons/oauth/kp/internal/database"
	mongodb "github.com/sing3demons/oauth/kp/internal/database"
	"github.com/sing3demons/oauth/kp/pkg/logAction"
	"github.com/sing3demons/oauth/kp/pkg/logger"
	"github.com/sing3demons/oauth/kp/pkg/mlog"
	"github.com/sing3demons/oauth/kp/pkg/query"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type ISigningKeyRepository interface {
	// Find() ([]SigningKey, error)
	FindKeyOidcByAlgorithm(ctx context.Context) ([]SigningKey, error)
	FindByAlgorithm(ctx context.Context, alg string) (SigningKey, error)
	LoadActiveKeyByAlgorithm() ([]SigningKey, error)
	// DeactivateKeyByKID(kid string) error
	// CleanupOldInactiveKeys(olderThan time.Duration) error
	FindByKID(ctx context.Context, kid string) (SigningKey, error)
	UpdateSigningKey(ctx context.Context, conf_mongo_signing_key_oidc_exp int, key SigningKey) error
}

type JWTAlgorithm string

const (
	JWTAlgorithmRS256    JWTAlgorithm = "RS256"
	JWTAlgorithmES256    JWTAlgorithm = "ES256"
	SigningKeyCollection              = "signing_keys"
)

func IsValidAlgorithm(alg string) bool {
	switch JWTAlgorithm(alg) {
	case JWTAlgorithmRS256, JWTAlgorithmES256:
		return true
	default:
		return false
	}
}
func GetSupportedAlgorithms(alg []string) []JWTAlgorithm {
	var supported []JWTAlgorithm
	for _, a := range alg {
		if IsValidAlgorithm(a) {
			supported = append(supported, JWTAlgorithm(a))
		}
	}
	return supported
}

type SigningKeyRepository struct {
	collection *mongo.Collection
	cache      database.IRedisClient
	expiresAt  time.Duration
	algorithms []string
}

func NewSigningKeyRepository(db *mongodb.Database, cache database.IRedisClient) ISigningKeyRepository {
	alg := []string{}
	for _, a := range GetSupportedAlgorithms([]string{"RS256", "ES256"}) {
		alg = append(alg, string(a))
	}
	repo := &SigningKeyRepository{
		collection: db.GetCollection(SigningKeyCollection),
		expiresAt:  30 * 24 * time.Hour, // 30 days
		algorithms: alg,
		cache:      cache,
	}

	indexes := []mongo.IndexModel{
		// kid unique
		{
			Keys: bson.D{{Key: "kid", Value: 1}},
			Options: options.Index().
				SetUnique(true).
				SetName("uniq_kid"),
		},

		// algorithm index
		{
			Keys: bson.D{{Key: "algorithm", Value: 1}},
			Options: options.Index().
				SetName("idx_algorithm"),
		},

		// active index
		{
			Keys: bson.D{{Key: "active", Value: 1}},
			Options: options.Index().
				SetName("idx_active"),
		},

		// compound: algorithm + active
		{
			Keys: bson.D{
				{Key: "algorithm", Value: 1},
				{Key: "active", Value: 1},
			},
			Options: options.Index().
				SetName("idx_algorithm_active"),
		},

		// unique: only one active key per algorithm
		{
			Keys: bson.D{
				{Key: "algorithm", Value: 1},
				{Key: "active", Value: 1},
			},
			Options: options.Index().
				SetUnique(true).
				SetPartialFilterExpression(
					bson.D{{Key: "active", Value: true}},
				).
				SetName("uniq_active_algorithm"),
		},

		// TTL: delete expired inactive keys
		{
			Keys: bson.D{{Key: "expiresAt", Value: 1}},
			Options: options.Index().
				SetExpireAfterSeconds(0).
				SetPartialFilterExpression(
					bson.D{{Key: "active", Value: false}},
				).
				SetName("ttl_expired_inactive"),
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_, err := repo.collection.Indexes().CreateMany(ctx, indexes)
	if err != nil {
		panic("failed to create signing keys indexes: " + err.Error())
	}

	return repo
}

func (j *SigningKeyRepository) generateRS256KeyPair() (privatePEM string, publicPEM string, err error) {
	// 1. Generate RSA key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", err
	}

	// 2. Encode private key (PKCS1)
	privateBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	privatePEM = string(pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateBytes,
	}))

	// 3. Encode public key
	publicBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return "", "", err
	}

	publicPEM = string(pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicBytes,
	}))

	return privatePEM, publicPEM, nil
}
func (j *SigningKeyRepository) generateES256KeyPair() (privatePEM string, publicPEM string, err error) {
	// 1. Generate ECDSA key (P-256)
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", err
	}

	// 2. Encode private key (PKCS8)
	privateBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return "", "", err
	}

	privatePEM = string(pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privateBytes,
	}))

	// 3. Encode public key
	publicBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return "", "", err
	}

	publicPEM = string(pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicBytes,
	}))

	return privatePEM, publicPEM, nil
}
func (j *SigningKeyRepository) generateKeyPair(alg string) (string, string, error) {
	switch alg {
	case "RS256":
		return j.generateRS256KeyPair()
	case "ES256":
		return j.generateES256KeyPair()
	default:
		return "", "", errors.New("unsupported algorithm")
	}
}
func (j *SigningKeyRepository) generateKID(alg string, publicKeyPEM string) string {
	hash := sha256.Sum256([]byte(publicKeyPEM))

	// short & jwt-friendly
	fingerprint := base64.RawURLEncoding.EncodeToString(hash[:8])

	return string(alg) + "-" + fingerprint
}
func (j *SigningKeyRepository) LoadActiveKeyByAlgorithm() ([]SigningKey, error) {
	if len(j.algorithms) == 0 {
		return nil, errors.New("no algorithms specified")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	filter := bson.M{
		"algorithm": bson.M{"$in": j.algorithms},
		"active":    true,
	}

	cursor, err := j.collection.Find(ctx, filter)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var keys []SigningKey
	for cursor.Next(ctx) {
		key := SigningKey{}
		if err := cursor.Decode(&key); err != nil {
			continue
		}
		keys = append(keys, key)
	}

	for _, alg := range j.algorithms {
		found := false
		for _, key := range keys {
			if string(key.Algorithm) == alg {
				found = true
				break
			}
		}
		if !found {
			// Generate new key pair
			privateKey, publicKey, err := j.generateKeyPair(alg)
			if err != nil {
				return nil, err
			}

			kid := j.generateKID(alg, publicKey)

			now := time.Now()
			expires := now.Add(j.expiresAt)
			newKey := SigningKey{
				KID:        kid,
				Algorithm:  JWTAlgorithm(alg),
				PrivateKey: privateKey,
				PublicKey:  publicKey,
				Active:     true,
				CreatedAt:  now,
				ExpiresAt:  &expires,
			}

			_, err = j.collection.InsertOne(ctx, newKey)
			if err != nil {
				return nil, err
			}

			keys = append(keys, newKey)
		}
	}

	return keys, nil
}

func (j *SigningKeyRepository) FindByKID(c context.Context, kid string) (SigningKey, error) {
	if kid == "" {
		return SigningKey{}, errors.New("kid is required")
	}
	cacheKey := "signing_key_kid_" + kid
	val, err := j.cache.Get(c, cacheKey)
	if err == nil && val != "" {
		var key SigningKey
		err = json.Unmarshal([]byte(val), &key)
		if err == nil {
			return key, nil
		}
	}
	start := time.Now()
	log := mlog.L(c)

	ctx, cancel := context.WithTimeout(c, 15*time.Second)
	defer cancel()
	filter := bson.M{
		"kid":    kid,
		"active": true,
	}

	raw := query.GenerateFindQuery(j.collection.Name(), filter)
	log.SetDependencyMetadata(logger.DependencyMetadata{
		Dependency: j.collection.Name(),
	}).Debug(logAction.DB_REQUEST(logAction.DB_READ, raw), filter)

	var key SigningKey
	err = j.collection.FindOne(ctx, filter).Decode(&key)
	elapsedMs := time.Since(start).Milliseconds()

	result := map[string]any{}
	if err != nil {
		result = map[string]any{
			"error": err.Error(),
		}
		log.SetDependencyMetadata(logger.DependencyMetadata{
			Dependency:   j.collection.Name(),
			ResponseTime: elapsedMs,
		}).Debug(logAction.DB_RESPONSE(logAction.DB_READ, "mongo response"), result)
	} else {
		result = map[string]any{
			"data": key,
		}

		maskingRules := []logger.MaskingRule{
			{
				Field: "data.PrivateKey", Type: logger.MaskingTypeFull,
			},
			{
				Field: "data.PublicKey", Type: logger.MaskingTypeFull,
			},
		}
		log.SetDependencyMetadata(logger.DependencyMetadata{
			Dependency:   j.collection.Name(),
			ResponseTime: elapsedMs,
		}).Debug(logAction.DB_RESPONSE(logAction.DB_READ, "mongo response"), result, maskingRules...)

		// cache the key
		exp := 30 * time.Minute
		if key.ExpiresAt != nil {
			ttl := time.Until(*key.ExpiresAt)
			if ttl < exp {
				exp = ttl
			}
		}
		j.cache.Set(c, cacheKey, key, exp)
	}

	return key, err
}

func (j *SigningKeyRepository) FindKeyOidcByAlgorithm(c context.Context) ([]SigningKey, error) {
	if len(j.algorithms) == 0 {
		return nil, errors.New("no algorithms specified")
	}

	start := time.Now()
	log := mlog.L(c)

	cacheKey := "signing_keys_oidc"
	val, err := j.cache.Get(c, cacheKey)
	if err == nil && val != "" {
		var keys []SigningKey
		err = json.Unmarshal([]byte(val), &keys)
		if err == nil && len(keys) == len(j.algorithms) {
			return keys, nil
		} else {
			j.cache.Del(c, cacheKey)
		}
	}

	ctx, cancel := context.WithTimeout(c, 15*time.Second)
	defer cancel()

	filter := bson.M{
		"algorithm": bson.M{"$in": j.algorithms},
		"active":    true,
	}
	raw := query.GenerateFindQuery(j.collection.Name(), filter)
	log.SetDependencyMetadata(logger.DependencyMetadata{
		Dependency: j.collection.Name(),
	}).Debug(logAction.DB_REQUEST(logAction.DB_READ, raw), filter)
	cursor, err := j.collection.Find(ctx, filter)

	elapsedMs := time.Since(start).Milliseconds()
	if err != nil {
		log.SetDependencyMetadata(logger.DependencyMetadata{
			Dependency:   j.collection.Name(),
			ResponseTime: elapsedMs,
		}).Debug(logAction.DB_RESPONSE(logAction.DB_READ, "mongo response"), map[string]any{
			"error": err.Error(),
		})
		return nil, err
	}

	defer cursor.Close(ctx)

	var keys []SigningKey
	for cursor.Next(ctx) {
		key := SigningKey{}
		if err := cursor.Decode(&key); err != nil {
			log.AddMetadata("error", err.Error())
			continue
		}

		j.UpdateSigningKey(c, 10, key)

		keys = append(keys, key)
	}

	for _, alg := range j.algorithms {
		found := false
		for _, key := range keys {
			if string(key.Algorithm) == alg {
				found = true
				break
			}
		}
		if !found {
			// Generate new key pair
			privateKey, publicKey, err := j.generateKeyPair(alg)
			if err != nil {
				return nil, err
			}

			kid := j.generateKID(alg, publicKey)

			now := time.Now()
			expires := now.Add(j.expiresAt)
			newKey := SigningKey{
				KID:        kid,
				Algorithm:  JWTAlgorithm(alg),
				PrivateKey: privateKey,
				PublicKey:  publicKey,
				Active:     true,
				CreatedAt:  now,
				ExpiresAt:  &expires,
			}

			s := time.Now()
			raw := query.GenerateInsertQuery(j.collection.Name(), newKey)
			log.SetDependencyMetadata(logger.DependencyMetadata{
				Dependency: j.collection.Name(),
			}).Debug(logAction.DB_REQUEST(logAction.DB_CREATE, raw), newKey)

			result, err := j.collection.InsertOne(ctx, newKey)
			elapsedInsertMs := time.Since(s).Milliseconds()
			if err != nil {
				log.SetDependencyMetadata(logger.DependencyMetadata{
					Dependency:   j.collection.Name(),
					ResponseTime: elapsedInsertMs,
				}).Debug(logAction.DB_RESPONSE(logAction.DB_CREATE, "mongo response"), map[string]any{
					"error": err.Error(),
				})
				return nil, err
			}

			log.SetDependencyMetadata(logger.DependencyMetadata{
				Dependency:   j.collection.Name(),
				ResponseTime: elapsedInsertMs,
			}).Debug(logAction.DB_RESPONSE(logAction.DB_CREATE, "mongo response"), map[string]any{
				"data": result,
			})

			keys = append(keys, newKey)
		}
	}

	// cache the keys
	exp := 30 * time.Minute
	j.cache.Set(c, cacheKey, keys, exp)

	return keys, nil
}

func (j *SigningKeyRepository) FindByAlgorithm(c context.Context, alg string) (SigningKey, error) {
	if alg == "" {
		return SigningKey{}, errors.New("algorithm is required")
	}
	cacheKey := "signing_key_" + alg
	val, err := j.cache.Get(c, cacheKey)
	if err == nil && val != "" {
		var key SigningKey
		err = json.Unmarshal([]byte(val), &key)
		if err == nil {
			return key, nil
		}
	}
	start := time.Now()
	log := mlog.L(c)

	ctx, cancel := context.WithTimeout(c, 15*time.Second)
	defer cancel()
	filter := bson.M{
		"algorithm": alg,
		"active":    true,
		"expiresAt": bson.M{"$gt": time.Now()},
	}

	raw := query.GenerateFindQuery(j.collection.Name(), filter)
	log.SetDependencyMetadata(logger.DependencyMetadata{
		Dependency: j.collection.Name(),
	}).Debug(logAction.DB_REQUEST(logAction.DB_READ, raw), filter)

	var key SigningKey
	err = j.collection.FindOne(ctx, filter).Decode(&key)
	elapsedMs := time.Since(start).Milliseconds()

	result := map[string]any{}
	if err != nil {
		result = map[string]any{
			"error": err.Error(),
		}
		log.SetDependencyMetadata(logger.DependencyMetadata{
			Dependency:   j.collection.Name(),
			ResponseTime: elapsedMs,
		}).Debug(logAction.DB_RESPONSE(logAction.DB_READ, "mongo response"), result)
	} else {
		result = map[string]any{
			"data": key,
		}

		maskingRules := []logger.MaskingRule{
			{
				Field: "data.PrivateKey", Type: logger.MaskingTypeFull,
			},
			{
				Field: "data.PublicKey", Type: logger.MaskingTypeFull,
			},
		}
		log.SetDependencyMetadata(logger.DependencyMetadata{
			Dependency:   j.collection.Name(),
			ResponseTime: elapsedMs,
		}).Debug(logAction.DB_RESPONSE(logAction.DB_READ, "mongo response"), result, maskingRules...)

		// cache the key
		exp := 15 * time.Minute
		if key.ExpiresAt != nil {
			ttl := time.Until(*key.ExpiresAt)
			if ttl < exp {
				exp = ttl
			}
		}
		j.cache.Set(c, cacheKey, key, exp)
	}

	return key, err
}

func (j *SigningKeyRepository) UpdateSigningKey(c context.Context, conf_mongo_signing_key_oidc_exp int, key SigningKey) error {
	currentTime := time.Now()
	expire_signing_key_oidc_exp := currentTime.Add(time.Duration(conf_mongo_signing_key_oidc_exp) * time.Second)
	if key.ExpiresAt == nil || key.ExpiresAt.Before(expire_signing_key_oidc_exp) {
		log := mlog.L(c)
		key.ExpiresAt = &expire_signing_key_oidc_exp
		ctx, cancel := context.WithTimeout(c, 15*time.Second)
		defer cancel()
		filter := bson.M{"kid": key.KID}
		update := bson.M{"$set": bson.M{"expiresAt": key.ExpiresAt}}
		raw := query.GenerateUpdateQuery(j.collection.Name(), filter, update)
		log.SetDependencyMetadata(logger.DependencyMetadata{
			Dependency: j.collection.Name(),
		}).Debug(logAction.DB_REQUEST(logAction.DB_UPDATE, raw), map[string]any{
			"filter": filter,
			"update": update,
		})

		r, err := j.collection.UpdateOne(ctx, filter, update)
		result := map[string]any{}
		if err != nil {
			result["error"] = err.Error()
		} else {
			result["data"] = r
		}
		elapsedMs := time.Since(currentTime).Milliseconds()
		log.SetDependencyMetadata(logger.DependencyMetadata{
			Dependency:   j.collection.Name(),
			ResponseTime: elapsedMs,
		}).Debug(logAction.DB_RESPONSE(logAction.DB_UPDATE, "mongo response"), result)
	}
	return nil
}
