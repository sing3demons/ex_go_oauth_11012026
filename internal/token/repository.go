package token

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

type AccessToken struct {
	AccessTokenId string `json:"access_token_id" bson:"access_token_id"` //jti
	AccessToken   string `json:"access_token" bson:"access_token"`
	ClientID      string `json:"client_id,omitempty" bson:"client_id,omitempty"`
	UserID        string `json:"user_id,omitempty" bson:"user_id,omitempty"`

	TokenType      string    `json:"token_type"`
	RefreshTokenId string    `json:"refresh_token_id,omitempty" bson:"refresh_token_id,omitempty"` //jti
	IDToken        string    `json:"id_token,omitempty" bson:"id_token,omitempty"`
	CreatedAt      time.Time `json:"created_at" bson:"created_at"`
	UpdatedAt      time.Time `json:"updated_at" bson:"updated_at"`
	ExpiresIn      int64     `json:"expires_in" bson:"expires_in"`
	ExpiresAt      time.Time `json:"expires_at" bson:"expires_at"`
}

func (a *AccessToken) IsExpired() bool {
	return time.Now().After(a.ExpiresAt)
}

type RefreshToken struct {
	RefreshTokenId string `json:"refresh_token_id" bson:"refresh_token_id"` //jti
	RefreshToken   string `json:"refresh_token" bson:"refresh_token"`

	AccessTokenId string `json:"access_token_id" bson:"access_token_id"` //jti
	AccessToken   string `json:"access_token" bson:"access_token"`
	IDToken       string `json:"id_token,omitempty" bson:"id_token,omitempty"`

	ClientID  string    `json:"client_id,omitempty" bson:"client_id,omitempty"`
	UserID    string    `json:"user_id,omitempty" bson:"user_id,omitempty"`
	CreatedAt time.Time `json:"created_at" bson:"created_at"`
	UpdatedAt time.Time `json:"updated_at" bson:"updated_at"`
	ExpiresIn int64     `json:"expires_in" bson:"expires_in"`
	ExpiresAt time.Time `json:"expires_at" bson:"expires_at"`
}

func (r *RefreshToken) IsExpired() bool {
	return time.Now().After(r.ExpiresAt)
}

const (
	dbTimeout = 15 * time.Second
)

type ITokenRepository interface {
	SaveAccessToken(ctx context.Context, token *AccessToken) error
	GetAccessTokenById(ctx context.Context, accessTokenId string) (*AccessToken, error)
	GetAccessTokenByToken(ctx context.Context, accessToken string) (*AccessToken, error)

	SaveRefreshToken(ctx context.Context, token *RefreshToken) error
	// insert or update refresh token
	UpsertRefreshToken(ctx context.Context, token *RefreshToken) error
	GetRefreshTokenById(ctx context.Context, refreshTokenId string) (*RefreshToken, error)
	GetRefreshTokenByToken(ctx context.Context, refreshToken string) (*RefreshToken, error)

	// insert or update (access token, refresh token)
	UpsertTokens(ctx context.Context, accessToken *AccessToken, refreshToken *RefreshToken) error
	DeleteTokens(ctx context.Context, refreshTokenId string) error
}

type MongoTokenRepository struct {
	collectionAccessToken  *mongo.Collection
	collectionRefreshToken *mongo.Collection
}

func NewMongoTokenRepository(db *database.Database) ITokenRepository {
	repo := &MongoTokenRepository{
		collectionAccessToken:  db.GetCollection("tokens"),
		collectionRefreshToken: db.GetCollection("refresh_tokens"),
	}

	// Create indexes if needed
	// access_token_id index
	repo.collectionAccessToken.Indexes().CreateMany(context.Background(), []mongo.IndexModel{
		{
			Keys: bson.D{{Key: "access_token_id", Value: 1}},
			Options: options.Index().
				SetUnique(true).
				SetName("uniq_access_token_id"),
		},
		{
			Keys: bson.D{{Key: "access_token", Value: 1}},
			Options: options.Index().
				SetUnique(true).
				SetName("uniq_access_token"),
		}, // expires_at index for TTL
		{
			Keys: bson.D{{Key: "expires_at", Value: 1}},
			Options: options.Index().
				SetExpireAfterSeconds(0).
				SetName("ttl_expired"),
		},
	})

	// refresh_token_id index
	repo.collectionRefreshToken.Indexes().CreateMany(context.Background(), []mongo.IndexModel{
		{
			Keys: bson.D{{Key: "refresh_token_id", Value: 1}},
			Options: options.Index().
				SetUnique(true).
				SetName("uniq_refresh_token_id"),
		},
		{
			Keys: bson.D{{Key: "refresh_token", Value: 1}},
			Options: options.Index().
				SetUnique(true).
				SetName("uniq_refresh_token"),
		}, // expires_at index for TTL
		{
			Keys: bson.D{{Key: "expires_at", Value: 1}},
			Options: options.Index().
				SetExpireAfterSeconds(0).
				SetName("ttl_expired"),
		},
	})

	return repo
}

func (r *MongoTokenRepository) SaveAccessToken(c context.Context, token *AccessToken) error {
	start := time.Now()
	log := mlog.L(c)
	ctx, cancel := context.WithTimeout(c, dbTimeout)
	defer cancel()

	raw := query.GenerateInsertQuery(r.collectionAccessToken.Name(), token)
	log.SetDependencyMetadata(logger.DependencyMetadata{
		Dependency: r.collectionAccessToken.Name(),
	}).Debug(logAction.DB_REQUEST(logAction.DB_CREATE, raw), token)

	result, err := r.collectionAccessToken.InsertOne(ctx, token)
	elapsedMs := time.Since(start).Milliseconds()

	data := map[string]any{}
	if err != nil {
		data["error"] = err.Error()
	} else {
		data["result"] = result
	}

	log.SetDependencyMetadata(logger.DependencyMetadata{
		Dependency:   r.collectionAccessToken.Name(),
		ResponseTime: elapsedMs,
	}).Debug(logAction.DB_RESPONSE(logAction.DB_CREATE, raw), data)
	return database.HandleMongoError(err)
}

func (r *MongoTokenRepository) GetAccessTokenById(c context.Context, accessTokenId string) (*AccessToken, error) {
	start := time.Now()
	log := mlog.L(c)
	ctx, cancel := context.WithTimeout(c, dbTimeout)
	defer cancel()

	filter := bson.M{"access_token_id": accessTokenId}

	raw := query.GenerateFindQuery(r.collectionAccessToken.Name(), filter)
	log.SetDependencyMetadata(logger.DependencyMetadata{
		Dependency: r.collectionAccessToken.Name(),
	}).Debug(logAction.DB_REQUEST(logAction.DB_READ, raw), filter)

	result := &AccessToken{}
	err := r.collectionAccessToken.FindOne(ctx, filter).Decode(result)
	elapsedMs := time.Since(start).Milliseconds()

	data := map[string]any{}

	if err != nil {
		data["error"] = err.Error()
	} else {
		data["data"] = result
	}

	log.SetDependencyMetadata(logger.DependencyMetadata{
		Dependency:   r.collectionAccessToken.Name(),
		ResponseTime: elapsedMs,
	}).Debug(logAction.DB_RESPONSE(logAction.DB_READ, raw), data)

	return result, database.HandleMongoError(err)
}

func (r *MongoTokenRepository) GetAccessTokenByToken(c context.Context, accessToken string) (*AccessToken, error) {
	start := time.Now()
	log := mlog.L(c)
	ctx, cancel := context.WithTimeout(c, dbTimeout)
	defer cancel()

	filter := bson.M{"access_token": accessToken}
	raw := query.GenerateFindQuery(r.collectionAccessToken.Name(), filter)
	log.SetDependencyMetadata(logger.DependencyMetadata{
		Dependency: r.collectionAccessToken.Name(),
	}).Debug(logAction.DB_REQUEST(logAction.DB_READ, raw), filter)

	result := &AccessToken{}
	err := r.collectionAccessToken.FindOne(ctx, filter).Decode(result)
	elapsedMs := time.Since(start).Milliseconds()
	data := map[string]any{}
	if err != nil {
		data["error"] = err.Error()
	} else {
		data["data"] = result
	}
	log.SetDependencyMetadata(logger.DependencyMetadata{
		Dependency:   r.collectionAccessToken.Name(),
		ResponseTime: elapsedMs,
	}).Debug(logAction.DB_RESPONSE(logAction.DB_READ, raw), data)

	return result, database.HandleMongoError(err)
}

func (r *MongoTokenRepository) SaveRefreshToken(c context.Context, token *RefreshToken) error {
	start := time.Now()
	log := mlog.L(c)
	ctx, cancel := context.WithTimeout(c, dbTimeout)
	defer cancel()
	raw := query.GenerateInsertQuery(r.collectionRefreshToken.Name(), token)
	log.SetDependencyMetadata(logger.DependencyMetadata{
		Dependency: r.collectionRefreshToken.Name(),
	}).Debug(logAction.DB_REQUEST(logAction.DB_CREATE, raw), token)

	_, err := r.collectionRefreshToken.InsertOne(ctx, token)
	elapsedMs := time.Since(start).Milliseconds()

	data := map[string]any{}
	if err != nil {
		data["error"] = err.Error()
	} else {
		data["data"] = "inserted"
	}

	log.SetDependencyMetadata(logger.DependencyMetadata{
		Dependency:   r.collectionRefreshToken.Name(),
		ResponseTime: elapsedMs,
	}).Debug(logAction.DB_RESPONSE(logAction.DB_CREATE, raw), data)

	return database.HandleMongoError(err)
}

func (r *MongoTokenRepository) GetRefreshTokenById(c context.Context, refreshTokenId string) (*RefreshToken, error) {
	start := time.Now()
	log := mlog.L(c)
	ctx, cancel := context.WithTimeout(c, dbTimeout)
	defer cancel()

	filter := bson.M{"refresh_token_id": refreshTokenId}
	raw := query.GenerateFindQuery(r.collectionRefreshToken.Name(), filter)
	log.SetDependencyMetadata(logger.DependencyMetadata{
		Dependency: r.collectionRefreshToken.Name(),
	}).Debug(logAction.DB_REQUEST(logAction.DB_READ, raw), filter)

	result := &RefreshToken{}
	err := r.collectionRefreshToken.FindOne(ctx, filter).Decode(result)
	elapsedMs := time.Since(start).Milliseconds()

	data := map[string]any{}
	if err != nil {
		data["error"] = err.Error()
	} else {
		data["data"] = result
	}

	log.SetDependencyMetadata(logger.DependencyMetadata{
		Dependency:   r.collectionRefreshToken.Name(),
		ResponseTime: elapsedMs,
	}).Debug(logAction.DB_RESPONSE(logAction.DB_READ, raw), data)

	return result, database.HandleMongoError(err)
}

func (r *MongoTokenRepository) GetRefreshTokenByToken(c context.Context, refreshToken string) (*RefreshToken, error) {
	start := time.Now()
	log := mlog.L(c)
	ctx, cancel := context.WithTimeout(c, dbTimeout)
	defer cancel()

	filter := bson.M{"refresh_token": refreshToken}
	raw := query.GenerateFindQuery(r.collectionRefreshToken.Name(), filter)
	log.SetDependencyMetadata(logger.DependencyMetadata{
		Dependency: r.collectionRefreshToken.Name(),
	}).Debug(logAction.DB_REQUEST(logAction.DB_READ, raw), filter)

	result := &RefreshToken{}
	err := r.collectionRefreshToken.FindOne(ctx, filter).Decode(result)
	elapsedMs := time.Since(start).Milliseconds()

	data := map[string]any{}
	if err != nil {
		data["error"] = err.Error()
	} else {
		data["data"] = result
	}

	log.SetDependencyMetadata(logger.DependencyMetadata{
		Dependency:   r.collectionRefreshToken.Name(),
		ResponseTime: elapsedMs,
	}).Debug(logAction.DB_RESPONSE(logAction.DB_READ, raw), data)

	return result, database.HandleMongoError(err)
}

func (r *MongoTokenRepository) UpsertRefreshToken(c context.Context, token *RefreshToken) error {
	start := time.Now()
	log := mlog.L(c)
	ctx, cancel := context.WithTimeout(c, dbTimeout)
	defer cancel()

	filter := bson.M{"refresh_token_id": token.RefreshTokenId}
	update := bson.M{
		"$set": token,
		"$setOnInsert": bson.M{
			"createdAt": time.Now(),
		},
	}

	raw := query.GenerateFindOneAndUpdateQuery(r.collectionRefreshToken.Name(), filter, update)
	log.SetDependencyMetadata(logger.DependencyMetadata{
		Dependency: r.collectionRefreshToken.Name(),
	}).Debug(logAction.DB_REQUEST(logAction.DB_UPDATE, raw), map[string]any{
		"filter": filter,
		"update": update,
	})

	opts := options.FindOneAndUpdate().
		SetUpsert(true).
		SetReturnDocument(options.After)

	err := r.collectionRefreshToken.FindOneAndUpdate(ctx, filter, update, opts).Decode(&token)
	elapsedMs := time.Since(start).Milliseconds()

	data := map[string]any{}
	if err != nil {
		data["error"] = err.Error()
	} else {
		data["result"] = token
	}

	log.SetDependencyMetadata(logger.DependencyMetadata{
		Dependency:   r.collectionRefreshToken.Name(),
		ResponseTime: elapsedMs,
	}).Debug(logAction.DB_RESPONSE(logAction.DB_UPDATE, raw), data)

	return database.HandleMongoError(err)
}
func (r *MongoTokenRepository) UpsertTokens(c context.Context, accessToken *AccessToken, refreshToken *RefreshToken) error {
	start := time.Now()
	log := mlog.L(c)
	ctx, cancel := context.WithTimeout(c, dbTimeout)
	defer cancel()

	opts := options.FindOneAndUpdate().
		SetUpsert(true).
		SetReturnDocument(options.After)

	accessToken.UpdatedAt = time.Now()
	filterAccess := bson.M{"access_token_id": accessToken.AccessTokenId}
	updateAccess := bson.M{
		"$set": accessToken,
		"$setOnInsert": bson.M{
			"createdAt": time.Now(),
		},
	}

	rawAccess := query.GenerateUpdateQuery(r.collectionAccessToken.Name(), filterAccess, accessToken)
	log.SetDependencyMetadata(logger.DependencyMetadata{
		Dependency: r.collectionAccessToken.Name(),
	}).Debug(logAction.DB_REQUEST(logAction.DB_UPDATE, rawAccess), map[string]any{
		"filter": filterAccess,
		"update": updateAccess,
	})

	err := r.collectionAccessToken.FindOneAndUpdate(ctx, filterAccess, updateAccess, opts).Decode(&accessToken)
	elapsedMs := time.Since(start).Milliseconds()

	data := map[string]any{}
	if err != nil {
		data["error"] = err.Error()
	} else {
		data["result"] = accessToken
	}

	log.SetDependencyMetadata(logger.DependencyMetadata{
		Dependency:   r.collectionAccessToken.Name(),
		ResponseTime: elapsedMs,
	}).Debug(logAction.DB_RESPONSE(logAction.DB_UPDATE, rawAccess), data)

	if err != nil {
		return database.HandleMongoError(err)
	}

	// Upsert Refresh Token
	start = time.Now()
	refreshToken.UpdatedAt = time.Now()
	filterRefresh := bson.M{"refresh_token_id": refreshToken.RefreshTokenId}
	updateRefresh := bson.M{
		"$set": refreshToken,
		"$setOnInsert": bson.M{
			"createdAt": time.Now(),
		},
	}

	rawRefresh := query.GenerateUpdateQuery(r.collectionRefreshToken.Name(), filterRefresh, refreshToken)
	log.SetDependencyMetadata(logger.DependencyMetadata{
		Dependency: r.collectionRefreshToken.Name(),
	}).Debug(logAction.DB_REQUEST(logAction.DB_UPDATE, rawRefresh), map[string]any{
		"filter": filterRefresh,
		"update": updateRefresh,
	})

	err = r.collectionRefreshToken.FindOneAndUpdate(ctx, filterRefresh, updateRefresh, opts).Decode(&refreshToken)
	elapsedMs = time.Since(start).Milliseconds()

	data = map[string]any{}
	if err != nil {
		data["error"] = err.Error()
	} else {
		data["result"] = refreshToken
	}

	log.SetDependencyMetadata(logger.DependencyMetadata{
		Dependency:   r.collectionRefreshToken.Name(),
		ResponseTime: elapsedMs,
	}).Debug(logAction.DB_RESPONSE(logAction.DB_UPDATE, rawRefresh), data)

	return database.HandleMongoError(err)
}

func (r *MongoTokenRepository) UpsertTokensWithTransaction(c context.Context, accessToken *AccessToken, refreshToken *RefreshToken) error {
	start := time.Now()
	log := mlog.L(c)
	ctx, cancel := context.WithTimeout(c, dbTimeout)
	defer cancel()

	session, err := r.collectionAccessToken.Database().Client().StartSession()
	if err != nil {
		return database.HandleMongoError(err)
	}
	defer session.EndSession(ctx)

	callback := func(sessCtx mongo.SessionContext) (any, error) {
		// Upsert Access Token
		accessFilter := bson.M{"access_token_id": accessToken.AccessTokenId}
		accessUpdate := bson.M{
			"$set": accessToken,
			"$setOnInsert": bson.M{
				"createdAt": time.Now(),
			},
		}
		_, err := r.collectionAccessToken.UpdateOne(sessCtx, accessFilter, accessUpdate, options.Update().SetUpsert(true))
		if err != nil {
			return nil, err
		}

		// Upsert Refresh Token
		refreshFilter := bson.M{"refresh_token_id": refreshToken.RefreshTokenId}
		refreshUpdate := bson.M{
			"$set": refreshToken,
			"$setOnInsert": bson.M{
				"createdAt": time.Now(),
			},
		}
		_, err = r.collectionRefreshToken.UpdateOne(sessCtx, refreshFilter, refreshUpdate, options.Update().SetUpsert(true))
		if err != nil {
			return nil, err
		}

		return nil, nil
	}

	rawAccess := query.GenerateUpdateQuery(r.collectionAccessToken.Name(), bson.M{"access_token_id": accessToken.AccessTokenId}, accessToken)
	rawRefresh := query.GenerateUpdateQuery(r.collectionRefreshToken.Name(), bson.M{"refresh_token_id": refreshToken.RefreshTokenId}, refreshToken)
	log.SetDependencyMetadata(logger.DependencyMetadata{
		Dependency: r.collectionAccessToken.Name(),
	}).Debug(logAction.DB_REQUEST(logAction.DB_UPDATE, rawAccess+"; "+rawRefresh), map[string]any{
		"access_token":  accessToken,
		"refresh_token": refreshToken,
	})

	_, err = session.WithTransaction(ctx, callback)
	elapsedMs := time.Since(start).Milliseconds()

	data := map[string]any{}
	if err != nil {
		data["error"] = err.Error()
	} else {
		data["result"] = "upserted"
	}

	log.SetDependencyMetadata(logger.DependencyMetadata{
		Dependency:   r.collectionAccessToken.Name(),
		ResponseTime: elapsedMs,
	}).Debug(logAction.DB_RESPONSE(logAction.DB_UPDATE, rawAccess+"; "+rawRefresh), data)

	return database.HandleMongoError(err)
}

func (r *MongoTokenRepository) DeleteTokens(c context.Context, refreshTokenId string) error {
	start := time.Now()
	log := mlog.L(c)
	ctx, cancel := context.WithTimeout(c, dbTimeout)
	defer cancel()

	filter := bson.M{"refresh_token_id": refreshTokenId}

	// delete access token

	rawAccess := query.GenerateDeleteQuery(r.collectionAccessToken.Name(), filter)
	log.SetDependencyMetadata(logger.DependencyMetadata{
		Dependency: r.collectionAccessToken.Name(),
	}).Debug(logAction.DB_REQUEST(logAction.DB_DELETE, rawAccess), filter)

	accessResult, err := r.collectionAccessToken.DeleteOne(ctx, filter)
	elapsedMs := time.Since(start).Milliseconds()

	accessData := map[string]any{}
	if err != nil {
		accessData["error"] = err.Error()
	} else {
		accessData["data"] = accessResult
	}

	log.SetDependencyMetadata(logger.DependencyMetadata{
		Dependency:   r.collectionAccessToken.Name(),
		ResponseTime: elapsedMs,
	}).Debug(logAction.DB_RESPONSE(logAction.DB_DELETE, rawAccess), accessData)

	start = time.Now()

	// delete refresh token

	raw := query.GenerateDeleteQuery(r.collectionRefreshToken.Name(), filter)
	log.SetDependencyMetadata(logger.DependencyMetadata{
		Dependency: r.collectionRefreshToken.Name(),
	}).Debug(logAction.DB_REQUEST(logAction.DB_DELETE, raw), filter)

	result, err := r.collectionRefreshToken.DeleteOne(ctx, filter)
	elapsedMs = time.Since(start).Milliseconds()

	data := map[string]any{}
	if err != nil {
		data["error"] = err.Error()
	} else {
		data["data"] = result
	}

	log.SetDependencyMetadata(logger.DependencyMetadata{
		Dependency:   r.collectionRefreshToken.Name(),
		ResponseTime: elapsedMs,
	}).Debug(logAction.DB_RESPONSE(logAction.DB_DELETE, raw), data)

	return nil
}
