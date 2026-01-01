package query

import (
	"strings"
	"testing"
)

func TestGenerateRawQuery(t *testing.T) {
	tests := []struct {
		name       string
		collection string
		queryType  QueryType
		data       interface{}
		want       string
	}{
		{
			name:       "insertOne with simple data",
			collection: "clients",
			queryType:  InsertOne,
			data: map[string]string{
				"id":   "xxx",
				"name": "test",
			},
			want: "db.clients.insertOne(",
		},
		{
			name:       "findOne with filter",
			collection: "users",
			queryType:  FindOne,
			data: map[string]string{
				"email": "test@example.com",
			},
			want: "db.users.findOne(",
		},
		{
			name:       "deleteOne with id",
			collection: "sessions",
			queryType:  DeleteOne,
			data: map[string]int{
				"session_id": 123,
			},
			want: "db.sessions.deleteOne(",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GenerateRawQuery(tt.collection, tt.queryType, tt.data)

			if !strings.HasPrefix(result, tt.want) {
				t.Errorf("GenerateRawQuery() = %s, want to start with %s", result, tt.want)
			}

			if !strings.Contains(result, tt.collection) {
				t.Errorf("GenerateRawQuery() result doesn't contain collection name %s", tt.collection)
			}

			if !strings.Contains(result, string(tt.queryType)) {
				t.Errorf("GenerateRawQuery() result doesn't contain query type %s", tt.queryType)
			}
		})
	}
}

func TestGenerateRawQueryWithFilter(t *testing.T) {
	tests := []struct {
		name       string
		collection string
		queryType  QueryType
		filter     interface{}
		data       interface{}
		want       string
	}{
		{
			name:       "updateOne with filter and update",
			collection: "clients",
			queryType:  UpdateOne,
			filter: map[string]string{
				"_id": "123",
			},
			data: map[string]string{
				"name": "updated",
			},
			want: "db.clients.updateOne(",
		},
		{
			name:       "deleteMany with filter",
			collection: "logs",
			queryType:  DeleteMany,
			filter: map[string]string{
				"level": "debug",
			},
			data: map[string]interface{}{},
			want: "db.logs.deleteMany(",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GenerateRawQueryWithFilter(tt.collection, tt.queryType, tt.filter, tt.data)

			if !strings.HasPrefix(result, tt.want) {
				t.Errorf("GenerateRawQueryWithFilter() = %s, want to start with %s", result, tt.want)
			}

			if !strings.Contains(result, tt.collection) {
				t.Errorf("GenerateRawQueryWithFilter() result doesn't contain collection name %s", tt.collection)
			}

			if !strings.Contains(result, string(tt.queryType)) {
				t.Errorf("GenerateRawQueryWithFilter() result doesn't contain query type %s", tt.queryType)
			}
		})
	}
}

func TestGenerateInsertQuery(t *testing.T) {
	data := map[string]interface{}{
		"id":    "xxx",
		"name":  "test client",
		"email": "client@example.com",
	}

	result := GenerateInsertQuery("clients", data)

	if !strings.Contains(result, "db.clients.insertOne") {
		t.Errorf("GenerateInsertQuery() = %s, expected to contain 'db.clients.insertOne'", result)
	}

	if !strings.Contains(result, "xxx") {
		t.Errorf("GenerateInsertQuery() result doesn't contain data value 'xxx'")
	}
}

func TestGenerateFindQuery(t *testing.T) {
	filter := map[string]string{
		"client_id": "123",
	}

	result := GenerateFindQuery("clients", filter)

	if !strings.Contains(result, "db.clients.findOne") {
		t.Errorf("GenerateFindQuery() = %s, expected to contain 'db.clients.findOne'", result)
	}

	if !strings.Contains(result, "123") {
		t.Errorf("GenerateFindQuery() result doesn't contain filter value '123'")
	}
}

func TestGenerateUpdateQuery(t *testing.T) {
	filter := map[string]string{
		"_id": "user123",
	}
	update := map[string]interface{}{
		"$set": map[string]string{
			"name": "new name",
		},
	}

	result := GenerateUpdateQuery("users", filter, update)

	if !strings.Contains(result, "db.users.updateOne") {
		t.Errorf("GenerateUpdateQuery() = %s, expected to contain 'db.users.updateOne'", result)
	}

	if !strings.Contains(result, "user123") {
		t.Errorf("GenerateUpdateQuery() result doesn't contain filter value")
	}
}

func TestGenerateDeleteQuery(t *testing.T) {
	filter := map[string]string{
		"_id": "session456",
	}

	result := GenerateDeleteQuery("sessions", filter)

	if !strings.Contains(result, "db.sessions.deleteOne") {
		t.Errorf("GenerateDeleteQuery() = %s, expected to contain 'db.sessions.deleteOne'", result)
	}

	if !strings.Contains(result, "session456") {
		t.Errorf("GenerateDeleteQuery() result doesn't contain filter value")
	}
}

func TestMongoJSONFormat(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "simple double quotes",
			input: `{"id":"123"}`,
			want:  `{'id':'123'}`,
		},
		{
			name:  "nested object",
			input: `{"user":{"name":"john","email":"john@example.com"}}`,
			want:  `{'user':{'name':'john','email':'john@example.com'}}`,
		},
		{
			name:  "array values",
			input: `{"tags":["tag1","tag2"]}`,
			want:  `{'tags':['tag1','tag2']}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := mongoJSONFormat(tt.input)
			if result != tt.want {
				t.Errorf("mongoJSONFormat() = %s, want %s", result, tt.want)
			}
		})
	}
}

func TestTruncateQuery(t *testing.T) {
	tests := []struct {
		name      string
		query     string
		maxLength int
		want      string
	}{
		{
			name:      "query shorter than max",
			query:     "db.clients.findOne({'id':'123'})",
			maxLength: 100,
			want:      "db.clients.findOne({'id':'123'})",
		},
		{
			name:      "query longer than max",
			query:     "db.clients.insertOne({'id':'123','name':'test','email':'test@example.com','phone':'1234567890'})",
			maxLength: 50,
			want:      "db.clients.insertOne({'id':'123','name':'test',...",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := TruncateQuery(tt.query, tt.maxLength)
			if result != tt.want {
				t.Errorf("TruncateQuery() = %s, want %s", result, tt.want)
			}
		})
	}
}

func TestGenerateQueryErrorHandling(t *testing.T) {
	// Test with nil data
	result := GenerateRawQuery("clients", InsertOne, nil)
	if !strings.Contains(result, "db.clients.insertOne") {
		t.Errorf("GenerateRawQuery() with nil data should still return valid query structure")
	}

	// Test with invalid queryType
	result = GenerateRawQuery("clients", QueryType("invalid"), map[string]string{"id": "123"})
	if !strings.Contains(result, "db.clients.invalid") {
		t.Errorf("GenerateRawQuery() should handle any query type")
	}
}

func BenchmarkGenerateRawQuery(b *testing.B) {
	data := map[string]interface{}{
		"id":    "xxx",
		"name":  "test",
		"email": "test@example.com",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		GenerateRawQuery("clients", InsertOne, data)
	}
}

func BenchmarkGenerateRawQueryWithFilter(b *testing.B) {
	filter := map[string]string{"_id": "123"}
	update := map[string]interface{}{
		"$set": map[string]string{"name": "new name"},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		GenerateRawQueryWithFilter("clients", UpdateOne, filter, update)
	}
}

func BenchmarkMongoJSONFormat(b *testing.B) {
	jsonStr := `{"id":"123","name":"test","email":"test@example.com"}`

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		mongoJSONFormat(jsonStr)
	}
}
