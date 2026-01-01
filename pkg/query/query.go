package query

import (
	"encoding/json"
	"fmt"
	"strings"
)

// QueryType represents the type of MongoDB operation
type QueryType string

const (
	InsertOne  QueryType = "insertOne"
	InsertMany QueryType = "insertMany"
	FindOne    QueryType = "findOne"
	FindMany   QueryType = "find"
	UpdateOne  QueryType = "updateOne"
	DeleteOne  QueryType = "deleteOne"
	DeleteMany QueryType = "deleteMany"
)

// GenerateRawQuery generates a MongoDB shell query string from data
// Example: GenerateRawQuery("clients", InsertOne, userData)
// Returns: "db.clients.insertOne({'field':'value'})"
func GenerateRawQuery(collection string, queryType QueryType, data interface{}) string {
	jsonData, err := json.Marshal(data)
	if err != nil {
		return fmt.Sprintf("db.%s.%s(...)", collection, queryType)
	}

	// Convert JSON to MongoDB shell format (single quotes instead of double quotes)
	queryStr := mongoJSONFormat(string(jsonData))

	return fmt.Sprintf("db.%s.%s(%s)", collection, queryType, queryStr)
}

// GenerateRawQueryWithFilter generates a MongoDB query with filter and update/data
// Example: GenerateRawQueryWithFilter("clients", UpdateOne, filter, update)
// Returns: "db.clients.updateOne({'_id':'xxx'}, {'$set':{'name':'new'}})"
func GenerateRawQueryWithFilter(collection string, queryType QueryType, filter interface{}, data interface{}) string {
	filterJSON, err := json.Marshal(filter)
	if err != nil {
		return fmt.Sprintf("db.%s.%s(...)", collection, queryType)
	}

	dataJSON, err := json.Marshal(data)
	if err != nil {
		return fmt.Sprintf("db.%s.%s(...)", collection, queryType)
	}

	filterStr := mongoJSONFormat(string(filterJSON))
	dataStr := mongoJSONFormat(string(dataJSON))

	return fmt.Sprintf("db.%s.%s(%s, %s)", collection, queryType, filterStr, dataStr)
}

// mongoJSONFormat converts JSON format to MongoDB shell format
// Changes double quotes to single quotes and handles special characters
func mongoJSONFormat(jsonStr string) string {
	// Replace double quotes with single quotes
	result := strings.ReplaceAll(jsonStr, `"`, `'`)

	// Unescape special characters that were escaped in JSON
	result = strings.ReplaceAll(result, `\'`, `'`) // Don't double-escape quotes
	result = strings.ReplaceAll(result, `\\`, `\`) // Fix backslashes

	return result
}

// GenerateInsertQuery is a convenience function for insertOne operations
func GenerateInsertQuery(collection string, data interface{}) string {
	return GenerateRawQuery(collection, InsertOne, data)
}

// GenerateFindQuery is a convenience function for findOne operations
func GenerateFindQuery(collection string, filter interface{}) string {
	return GenerateRawQuery(collection, FindOne, filter)
}

// GenerateUpdateQuery is a convenience function for updateOne operations
func GenerateUpdateQuery(collection string, filter interface{}, update interface{}) string {
	return GenerateRawQueryWithFilter(collection, UpdateOne, filter, update)
}

// GenerateDeleteQuery is a convenience function for deleteOne operations
func GenerateDeleteQuery(collection string, filter interface{}) string {
	return GenerateRawQuery(collection, DeleteOne, filter)
}

// TruncateQuery truncates a query string to a maximum length for logging
func TruncateQuery(query string, maxLength int) string {
	if len(query) <= maxLength {
		return query
	}
	return query[:maxLength-3] + "..."
}
