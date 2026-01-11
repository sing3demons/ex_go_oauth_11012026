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
	InsertAuthorizationCode(ctx context.Context, idTokenAlg string, code *AuthCode) (string, error)
	FindAuthorizationCodeByID(ctx context.Context, code string) (*AuthorizationCode, error)
	MarkAuthorizationCodeAsUsed(ctx context.Context, id string) error
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

func (r *AuthorizationCodeRepository) InsertAuthorizationCode(c context.Context, idTokenAlg string, authCode *AuthCode) (string, error) {
	start := time.Now()
	log := mlog.L(c)
	ctx, cancel := context.WithTimeout(c, r.dbTimeout)
	defer cancel()

	if idTokenAlg == "" {
		idTokenAlg = "RS256"
	}

	code := &AuthorizationCode{
		Used:       false,
		IDTokenAlg: idTokenAlg,
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

func (r *AuthorizationCodeRepository) FindAuthorizationCodeByID(c context.Context, code string) (*AuthorizationCode, error) {
	start := time.Now()
	log := mlog.L(c)
	ctx, cancel := context.WithTimeout(c, r.dbTimeout)
	defer cancel()

	filter := bson.M{"_id": code}
	raw := query.GenerateFindQuery(r.collection.Name(), filter)
	log.SetDependencyMetadata(logger.DependencyMetadata{
		Dependency: r.collection.Name(),
	}).Debug(logAction.DB_REQUEST(logAction.DB_READ, raw), filter)

	var data AuthorizationCode
	err := r.collection.FindOne(ctx, filter).Decode(&data)
	elapsedMs := time.Since(start).Milliseconds()

	result := map[string]any{}
	if err != nil {
		result["error"] = err.Error()
	} else {
		result["data"] = data
	}
	log.SetDependencyMetadata(logger.DependencyMetadata{
		Dependency:   r.collection.Name(),
		ResponseTime: elapsedMs,
	}).Debug(logAction.DB_RESPONSE(logAction.DB_READ, raw), result)

	return &data, database.HandleMongoError(err)
}

func (r *AuthorizationCodeRepository) MarkAuthorizationCodeAsUsed(c context.Context, id string) error {
	start := time.Now()
	log := mlog.L(c)
	ctx, cancel := context.WithTimeout(c, r.dbTimeout)
	defer cancel()

	filter := bson.M{"_id": id}
	update := bson.M{
		"$set": bson.M{
			"used":       true,
			"updated_at": time.Now(),
		},
	}

	raw := query.GenerateUpdateQuery(r.collection.Name(), filter, update)
	log.SetDependencyMetadata(logger.DependencyMetadata{
		Dependency: r.collection.Name(),
	}).Debug(logAction.DB_REQUEST(logAction.DB_UPDATE, raw), map[string]any{
		"filter": filter,
		"update": update,
	})

	_, err := r.collection.UpdateOne(ctx, filter, update)
	elapsedMs := time.Since(start).Milliseconds()

	result := map[string]any{}
	if err != nil {
		result["error"] = err.Error()
	} else {
		result["data"] = "updated"
	}
	log.SetDependencyMetadata(logger.DependencyMetadata{
		Dependency:   r.collection.Name(),
		ResponseTime: elapsedMs,
	}).Debug(logAction.DB_RESPONSE(logAction.DB_UPDATE, raw), result)

	return database.HandleMongoError(err)
}
