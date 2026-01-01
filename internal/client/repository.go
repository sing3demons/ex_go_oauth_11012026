package client

import (
	"context"
	"time"

	"github.com/google/uuid"
	mongodb "github.com/sing3demons/oauth/kp/internal/database"
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
	ctx, cancel := context.WithTimeout(c, 15*time.Second)
	defer cancel()
	if data.ClientID == "" {
		data.ClientID = uuid.New().String()
	}
	data.CreatedAt = time.Now()
	data.IDTokenAlgOrDefault()
	data.DefaultsTTL()
	_, err := r.collection.InsertOne(ctx, data)
	return err
}

func (r *ClientRepository) FindClientByID(c context.Context, clientID string) (OIDCClient, error) {
	filter := bson.M{
		"client_id": clientID,
	}
	var client OIDCClient
	ctx, cancel := context.WithTimeout(c, 15*time.Second)
	defer cancel()

	if err := r.collection.FindOne(ctx, filter).Decode(&client); err != nil {
		return OIDCClient{}, err
	}

	return client, nil
}
