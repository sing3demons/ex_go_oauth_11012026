package user

import (
	"context"
	"time"

	"github.com/sing3demons/oauth/kp/internal/database"
	"github.com/sing3demons/oauth/kp/pkg/logAction"
	"github.com/sing3demons/oauth/kp/pkg/logger"
	"github.com/sing3demons/oauth/kp/pkg/mlog"
	"github.com/sing3demons/oauth/kp/pkg/query"
	"github.com/sing3demons/oauth/kp/pkg/validate"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

const (
	dbTimeout = 15 * time.Second
)

type IUserRepository interface {
	// define user repository methods here
	CreateUser(ctx context.Context, user *ProfileModel) error
	// GetUserByID(ctx context.Context, id string) (*ProfileModel, error)
	// UpdateUser(ctx context.Context, user *ProfileModel) error
	// DeleteUser(ctx context.Context, id string) error
	FindUserByUsername(ctx context.Context, username string) (*ProfileModel, error)
	FindUserByID(ctx context.Context, id string, fields ...string) (*ProfileModel, error)
}

type UserRepository struct {
	collection *mongo.Collection
}

func NewUserRepository(db *database.Database) IUserRepository {
	return &UserRepository{
		collection: db.GetCollection("users"),
	}
}
func (r *UserRepository) CreateUser(c context.Context, user *ProfileModel) error {
	start := time.Now()
	log := mlog.L(c)
	ctx, cancel := context.WithTimeout(c, dbTimeout)
	defer cancel()

	masking := []logger.MaskingRule{
		{
			Field: "email",
			Type:  logger.MaskingTypeEmail,
		},
		{
			Field: "username",
			Type:  logger.MaskingTypePartial,
		},
		{
			Field: "password",
			Type:  logger.MaskingTypeFull,
		},
		{
			Field: "pin",
			Type:  logger.MaskingTypeFull,
		},
	}

	user.CreatedAt = time.Now()
	user.UpdatedAt = time.Now()

	raw := query.GenerateInsertQuery(r.collection.Name(), logger.MaskData(user, masking))
	log.SetDependencyMetadata(logger.DependencyMetadata{
		Dependency: r.collection.Name(),
	}).Debug(logAction.DB_REQUEST(logAction.DB_CREATE, raw), user, masking...)

	data, err := r.collection.InsertOne(ctx, user)
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
	}).Debug(logAction.DB_RESPONSE(logAction.DB_CREATE, "mongo response"), result)

	return database.HandleMongoError(err)
}
func (r *UserRepository) FindUserByUsername(c context.Context, username string) (*ProfileModel, error) {
	start := time.Now()
	log := mlog.L(c)
	ctx, cancel := context.WithTimeout(c, dbTimeout)
	defer cancel()

	user := &ProfileModel{}
	filter := bson.M{}
	masking := []logger.MaskingRule{}

	if validate.IsEmail(username) {
		filter["email"] = username
		masking = append(masking, logger.MaskingRule{
			Field: "email",
			Type:  logger.MaskingTypeEmail,
		})
	} else {
		filter["username"] = username
		masking = append(masking, logger.MaskingRule{
			Field: "username",
			Type:  logger.MaskingTypePartial,
		})
	}

	raw := query.GenerateFindQuery(r.collection.Name(), logger.MaskData(filter, masking))
	log.SetDependencyMetadata(logger.DependencyMetadata{
		Dependency: r.collection.Name(),
	}).Debug(logAction.DB_REQUEST(logAction.DB_READ, raw), filter, masking...)

	err := r.collection.FindOne(ctx, filter).Decode(&user)
	result := map[string]any{}
	maskingDbResponse := make([]logger.MaskingRule, 4)
	if err != nil {
		result["error"] = err.Error()
		user = nil
	} else {
		result["data"] = user
		maskingDbResponse = []logger.MaskingRule{
			{
				Field: "data.email",
				Type:  logger.MaskingTypeEmail,
			},
			{
				Field: "data.username",
				Type:  logger.MaskingTypePartial,
			},
			{
				Field: "data.password",
				Type:  logger.MaskingTypeFull,
			},
			{
				Field: "data.pin",
				Type:  logger.MaskingTypeFull,
			},
		}
	}
	elapsedMs := time.Since(start).Milliseconds()
	log.SetDependencyMetadata(logger.DependencyMetadata{
		Dependency:   r.collection.Name(),
		ResponseTime: elapsedMs,
	}).Debug(logAction.DB_RESPONSE(logAction.DB_READ, "mongo response"), result, maskingDbResponse...)

	return user, database.HandleMongoError(err)
}

func (r *UserRepository) FindUserByID(ctx context.Context, id string, fields ...string) (*ProfileModel, error) {
	start := time.Now()
	log := mlog.L(ctx)
	c, cancel := context.WithTimeout(ctx, dbTimeout)
	defer cancel()

	user := ProfileModel{}
	filter := bson.M{"_id": id}
	options := &options.FindOneOptions{}
	projection := bson.M{
		"password": 0,
		"pin":      0,
	}

	if len(fields) > 0 {
		for _, field := range fields {
			projection[field] = 1
		}
	}
	options.Projection = projection
	raw := query.GenerateFindQuery(r.collection.Name(), filter)
	log.SetDependencyMetadata(logger.DependencyMetadata{
		Dependency: r.collection.Name(),
	}).Debug(logAction.DB_REQUEST(logAction.DB_READ, raw), filter)

	err := r.collection.FindOne(c, filter, options).Decode(&user)
	elapsedMs := time.Since(start).Milliseconds()

	result := map[string]any{}
	if err != nil {
		result["error"] = err.Error()
	} else {
		result["data"] = user
	}
	log.SetDependencyMetadata(logger.DependencyMetadata{
		Dependency:   r.collection.Name(),
		ResponseTime: elapsedMs,
	}).Debug(logAction.DB_RESPONSE(logAction.DB_READ, "mongo response"), result)

	return &user, database.HandleMongoError(err)
}
