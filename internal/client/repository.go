package client

import (
	"context"
	"time"

	"github.com/google/uuid"
	mongodb "github.com/sing3demons/oauth/kp/internal/database"
	"github.com/sing3demons/oauth/kp/pkg/logAction"
	"github.com/sing3demons/oauth/kp/pkg/logger"
	"github.com/sing3demons/oauth/kp/pkg/mlog"
	"github.com/sing3demons/oauth/kp/pkg/query"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type ClientRepository struct {
	collection *mongo.Collection
}

type IClientRepository interface {
	InsertClient(c context.Context, data *OIDCClient) error
	FindClientByID(c context.Context, clientID string) (OIDCClient, error)
}

func NewClientRepository(db *mongodb.Database) IClientRepository {
	cr := &ClientRepository{
		collection: db.GetCollection("clients"),
	}
	indexes := []mongo.IndexModel{
		{
			Keys:    bson.D{{Key: "client_id", Value: 1}},
			Options: options.Index().SetUnique(true),
		},
		{
			Keys:    bson.D{{Key: "client_name", Value: 1}},
			Options: options.Index().SetUnique(true),
		},
	}
	_, err := cr.collection.Indexes().CreateMany(context.Background(), indexes)
	if err != nil {
		panic(err)
	}
	return cr
}

func (r *ClientRepository) InsertClient(c context.Context, data *OIDCClient) error {
	start := time.Now()
	log := mlog.L(c)
	ctx, cancel := context.WithTimeout(c, 15*time.Second)
	defer cancel()
	if data.ClientID == "" {
		data.ClientID = uuid.New().String()
	}
	data.CreatedAt = time.Now()
	data.IDTokenAlgOrDefault()
	data.DefaultsTTL()
	raw := query.GenerateInsertQuery(r.collection.Name(), data)
	log.SetDependencyMetadata(logger.DependencyMetadata{
		Dependency: r.collection.Name(),
	}).Debug(logAction.DB_REQUEST(logAction.DB_CREATE, raw), map[string]any{
		"body": data,
	})
	result, err := r.collection.InsertOne(ctx, data)
	elapsedMs := time.Since(start).Milliseconds()

	resp := map[string]any{}

	if err != nil {
		resp["error"] = err.Error()
	} else {
		resp["data"] = result
	}
	log.SetDependencyMetadata(logger.DependencyMetadata{
		Dependency:   r.collection.Name(),
		ResponseTime: elapsedMs,
	}).Debug(logAction.DB_RESPONSE(logAction.DB_CREATE, "mongo response"), resp)

	return err
}

func (r *ClientRepository) FindClientByID(c context.Context, clientID string) (OIDCClient, error) {
	start := time.Now()
	filter := bson.M{
		"client_id": clientID,
	}
	var client OIDCClient
	ctx, cancel := context.WithTimeout(c, 15*time.Second)
	defer cancel()

	raw := query.GenerateFindQuery(r.collection.Name(), filter)
	log := mlog.L(c)
	log.SetDependencyMetadata(logger.DependencyMetadata{
		Dependency: r.collection.Name(),
	}).Debug(logAction.DB_REQUEST(logAction.DB_READ, raw), filter)

	err := r.collection.FindOne(ctx, filter).Decode(&client)
	elapsedMs := time.Since(start).Milliseconds()
	result := map[string]any{}
	if err != nil {
		result["error"] = err.Error()
	} else {
		result["data"] = client
	}
	log.SetDependencyMetadata(logger.DependencyMetadata{
		Dependency:   r.collection.Name(),
		ResponseTime: elapsedMs,
	}).Debug(logAction.DB_RESPONSE(logAction.DB_READ, "mongo response"), result)

	return client, err
}
