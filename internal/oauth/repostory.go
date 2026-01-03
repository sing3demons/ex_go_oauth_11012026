package oauth

import (
	"context"
	"time"

	"github.com/sing3demons/oauth/kp/internal/database"
	"github.com/sing3demons/oauth/kp/pkg/logAction"
	"github.com/sing3demons/oauth/kp/pkg/logger"
	"github.com/sing3demons/oauth/kp/pkg/mlog"
	"github.com/sing3demons/oauth/kp/pkg/query"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type AuthorizationCodeRepository struct {
	collection *mongo.Collection
	dbTimeout  time.Duration
}

type IAuthorizationCodeRepository interface {
	InsertAuthorizationCode(ctx context.Context, code *AuthCode) (string, error)
	// FindAuthorizationCodeByID(ctx context.Context, id string) (*AuthorizationCode, error)
	// UpdateAuthorizationCode(ctx context.Context, id string) error
	// DeleteAuthorizationCodeByID(ctx context.Context, id string) error
	// update used = true
	// UpdateAuthorizationCodeUsed(ctx context.Context, id string) error
}

func NewAuthorizationCodeRepository(db *database.Database) IAuthorizationCodeRepository {
	repo := &AuthorizationCodeRepository{
		collection: db.GetCollection("authorization_codes"),
		dbTimeout:  15 * time.Second,
	}

	// Create indexes if needed
	// authcode_id index
	// expires_at index for TTL
	repo.collection.Indexes().CreateMany(context.Background(), []mongo.IndexModel{
		{
			Keys: bson.D{{Key: "authcode_id", Value: 1}},
			Options: options.Index().
				SetUnique(true).
				SetName("uniq_authcode_id"),
		},
		{
			Keys: bson.D{{Key: "expires_at", Value: 1}},
			Options: options.Index().
				SetExpireAfterSeconds(0).
				SetPartialFilterExpression(
					bson.D{{Key: "active", Value: false}},
				).
				SetName("ttl_expired_inactive"),
		},
	})
	return repo
}

func (r *AuthorizationCodeRepository) InsertAuthorizationCode(c context.Context, authCode *AuthCode) (string, error) {
	start := time.Now()
	log := mlog.L(c)
	ctx, cancel := context.WithTimeout(c, r.dbTimeout)
	defer cancel()

	code := &AuthorizationCode{
		Used: false,
	}
	code.AuthCode = *authCode

	code.CreatedAt = time.Now()

	code.ExpiresAt = code.CreatedAt.Add(30 * time.Minute)
	id := code.generateAuthCode()
	raw := query.GenerateInsertQuery(r.collection.Name(), code)
	log.SetDependencyMetadata(logger.DependencyMetadata{
		Dependency: r.collection.Name(),
	}).Debug(logAction.DB_REQUEST(logAction.DB_CREATE, raw), code)

	data, err := r.collection.InsertOne(ctx, code)
	elapsedMs := time.Since(start).Milliseconds()

	result := map[string]any{}
	if err != nil {
		id = ""
		result["error"] = err.Error()
	} else {
		result["data"] = data
	}
	log.SetDependencyMetadata(logger.DependencyMetadata{
		Dependency:   r.collection.Name(),
		ResponseTime: elapsedMs,
	}).Debug(logAction.DB_RESPONSE(logAction.DB_CREATE, "mongo response"), result)

	return id, database.HandleMongoError(err)
}
