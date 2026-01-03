package database

import (
	"context"
	"errors"
	"fmt"
	"time"

	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type Database struct {
	client *mongo.Client
	db     *mongo.Database
}

func NewDatabase(uri, dbName string) (*Database, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Set client options
	clientOptions := options.Client().ApplyURI(uri)

	// Connect to MongoDB
	client, err := mongo.Connect(ctx, clientOptions)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to MongoDB: %w", err)
	}

	// Ping the database
	if err := client.Ping(ctx, nil); err != nil {
		return nil, fmt.Errorf("failed to ping MongoDB: %w", err)
	}

	db := client.Database(dbName)

	return &Database{
		client: client,
		db:     db,
	}, nil
}

func (d *Database) GetCollection(name string) *mongo.Collection {
	return d.db.Collection(name)
}

func (d *Database) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return d.client.Disconnect(ctx)
}

func (d *Database) Ping() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return d.client.Ping(ctx, nil)
}

var (
	ErrDatabaseTimeout   = errors.New("timeout")
	ErrDuplicate         = errors.New("duplicate")
	ErrConnection        = errors.New("connection_error")
	ErrNotFound          = errors.New("not_found")
	ErrUnauthorized      = errors.New("unauthorized")
	ErrServerUnavailable = errors.New("server_unavailable")
)

// handleMongoError converts MongoDB errors to standardized errors
func HandleMongoError(err error) error {
	if err == nil {
		return nil
	}
	if err == mongo.ErrNoDocuments {
		return ErrNotFound
	}
	if mongo.IsTimeout(err) {
		return ErrDatabaseTimeout
	}
	if mongo.IsDuplicateKeyError(err) {
		return ErrDuplicate
	}
	if mongo.IsNetworkError(err) {
		return ErrConnection
	}
	if errors.Is(err, context.Canceled) {
		return ErrServerUnavailable
	}
	return err
}
