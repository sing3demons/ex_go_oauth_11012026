package session

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

type ISessionCodeRepository interface {
	Create(ctx context.Context, code *SessionCode) error
	FindByID(ctx context.Context, id string) (*SessionCode, error)
	DeleteByID(ctx context.Context, id string) error
	UpdateState(ctx context.Context, id string, state, login_hint string) error
}

type SessionCodeRepository struct {
	// db database.IDatabase
	collection *mongo.Collection
}

func NewSessionCodeRepository(db *database.Database) ISessionCodeRepository {
	repo := &SessionCodeRepository{
		collection: db.GetCollection("session_codes"),
	}
	indexes := []mongo.IndexModel{
		{
			Keys:    bson.D{{Key: "client_id", Value: 1}},
			Options: options.Index().SetUnique(true),
		},
		// TTL: delete expired inactive keys
		{
			Keys:    bson.D{{Key: "expires_at", Value: 1}},
			Options: options.Index().SetExpireAfterSeconds(0),
		},
	}

	repo.collection.Indexes().CreateMany(context.Background(), indexes)

	return repo
}

func (r *SessionCodeRepository) Create(c context.Context, code *SessionCode) error {
	start := time.Now()
	log := mlog.L(c)
	ctx, cancel := context.WithTimeout(c, 15*time.Second)
	defer cancel()

	code.Status = "next"
	if code.CreatedAt.IsZero() {
		code.CreatedAt = time.Now()
	}
	if code.UpdatedAt.IsZero() {
		code.UpdatedAt = time.Now()
	}
	if code.ExpiresAt.IsZero() {
		code.ExpiresAt = time.Now().Add(30 * time.Minute)
	}

	raw := query.GenerateInsertQuery(r.collection.Name(), code)
	log.SetDependencyMetadata(logger.DependencyMetadata{
		Dependency: r.collection.Name(),
	}).Debug(logAction.DB_REQUEST(logAction.DB_CREATE, raw), map[string]any{
		"document": code,
	})
	data, err := r.collection.InsertOne(ctx, code)
	result := map[string]any{}
	if err != nil {
		result["error"] = err.Error()
	} else {
		result["data"] = data
	}
	elapsedMs := time.Since(start).Milliseconds()
	log.SetDependencyMetadata(logger.DependencyMetadata{
		Dependency:   r.collection.Name(),
		ResponseTime: elapsedMs,
	}).Debug(logAction.DB_RESPONSE(logAction.DB_CREATE, "mongo response"), result)
	return database.HandleMongoError(err)
}

func (r *SessionCodeRepository) FindByID(c context.Context, id string) (*SessionCode, error) {
	start := time.Now()
	log := mlog.L(c)
	ctx, cancel := context.WithTimeout(c, 15*time.Second)
	defer cancel()

	var code SessionCode
	filter := bson.M{"_id": id}

	raw := query.GenerateFindQuery(r.collection.Name(), filter)
	log.SetDependencyMetadata(logger.DependencyMetadata{
		Dependency: r.collection.Name(),
	}).Debug(logAction.DB_REQUEST(logAction.DB_READ, raw), map[string]any{
		"filter": filter,
	})
	err := r.collection.FindOne(ctx, filter).Decode(&code)
	result := map[string]any{}
	if err != nil {
		result["error"] = err.Error()
	} else {
		result["data"] = code
	}
	elapsedMs := time.Since(start).Milliseconds()
	log.SetDependencyMetadata(logger.DependencyMetadata{
		Dependency:   r.collection.Name(),
		ResponseTime: elapsedMs,
	}).Debug(logAction.DB_RESPONSE(logAction.DB_READ, "mongo response"), result)
	return &code, database.HandleMongoError(err)
}

func (r *SessionCodeRepository) DeleteByID(c context.Context, id string) error {
	start := time.Now()
	log := mlog.L(c)
	ctx, cancel := context.WithTimeout(c, 15*time.Second)
	defer cancel()

	filter := bson.M{"client_id": id}

	raw := query.GenerateDeleteQuery(r.collection.Name(), filter)
	log.SetDependencyMetadata(logger.DependencyMetadata{
		Dependency: r.collection.Name(),
	}).Debug(logAction.DB_REQUEST(logAction.DB_DELETE, raw), map[string]any{
		"filter": filter,
	})

	data, err := r.collection.DeleteOne(ctx, filter)
	result := map[string]any{}
	if err != nil {
		result["error"] = err.Error()
	} else {
		result["data"] = data
	}
	elapsedMs := time.Since(start).Milliseconds()
	log.SetDependencyMetadata(logger.DependencyMetadata{
		Dependency:   r.collection.Name(),
		ResponseTime: elapsedMs,
	}).Debug(logAction.DB_RESPONSE(logAction.DB_DELETE, "mongo response"), result)
	return database.HandleMongoError(err)
}
func (r *SessionCodeRepository) UpdateState(c context.Context, id string, state, login_hint string) error {
	start := time.Now()
	log := mlog.L(c)
	ctx, cancel := context.WithTimeout(c, 15*time.Second)
	defer cancel()

	filter := bson.M{"client_id": id}
	update := bson.M{
		"$set": bson.M{
			"state":      state,
			"updated_at": time.Now(),
		},
	}
	if login_hint != "" {
		update["$set"].(bson.M)["login_hint"] = login_hint
	}

	raw := query.GenerateUpdateQuery(r.collection.Name(), filter, update)
	log.SetDependencyMetadata(logger.DependencyMetadata{
		Dependency: r.collection.Name(),
	}).Debug(logAction.DB_REQUEST(logAction.DB_UPDATE, raw), map[string]any{
		"filter": filter,
	})
	data, err := r.collection.UpdateOne(ctx, filter, update)
	result := map[string]any{}
	if err != nil {
		result["error"] = err.Error()
	} else {
		result["data"] = data
	}
	elapsedMs := time.Since(start).Milliseconds()
	log.SetDependencyMetadata(logger.DependencyMetadata{
		Dependency:   r.collection.Name(),
		ResponseTime: elapsedMs,
	}).Debug(logAction.DB_RESPONSE(logAction.DB_UPDATE, "mongo response"), result)
	return database.HandleMongoError(err)
}
