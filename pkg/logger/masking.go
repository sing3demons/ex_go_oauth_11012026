package logger

import (
	"encoding/json"
	"reflect"
	"strings"
)

type MaskingType string

const (
	MaskingTypeFull    MaskingType = "full"    // แสดงเป็น "***"
	MaskingTypePartial MaskingType = "partial" // แสดงบางส่วน เช่น "abc***xyz"
	MaskingTypeEmail   MaskingType = "email"   // แสดงเป็น "a***@example.com"
	MaskingTypeCard    MaskingType = "card"    // แสดงเป็น "****-****-****-1234"
	MaskingTypeFirstName MaskingType = "first_name" // แสดงเฉพาะชื่อจริง เช่น "J***"
	MaskingTypeLastName  MaskingType = "last_name"  // แสดงเฉพาะนามสกุล เช่น "D***"
	MaskingTypePhone     MaskingType = "phone"     // แสดงหมายเลขโทรศัพท์บางส่วน เช่น "
	MaskingTypeUsername  MaskingType = "username"  // แสดงชื่อผู้ใช้บางส่วน เช่น "user**"
)

type MaskingRule struct {
	Field   string      // path ใช้ dot notation เช่น "body.password", "result.*.username"
	Type    MaskingType // ประเภทการ mask
	IsArray bool        // true เมื่อต้องการ mask array elements
}

// MaskData applies masking rules to the data
func MaskData(data any, rules []MaskingRule) any {
	if len(rules) == 0 {
		return data
	}

	// Convert to map for easier manipulation
	var dataMap map[string]any

	jsonBytes, err := json.Marshal(data)
	if err != nil {
		return data
	}

	if err := json.Unmarshal(jsonBytes, &dataMap); err != nil {
		return data
	}

	for _, rule := range rules {
		applyMaskingRule(dataMap, rule.Field, rule.Type, rule.IsArray)
	}

	return dataMap
}

func applyMaskingRule(data map[string]any, path string, maskType MaskingType, isArray bool) {
	parts := strings.Split(path, ".")
	applyMaskingRecursive(data, parts, maskType, isArray)
}

func applyMaskingRecursive(data any, pathParts []string, maskType MaskingType, isArray bool) {
	if len(pathParts) == 0 {
		return
	}

	currentPart := pathParts[0]
	remainingParts := pathParts[1:]

	switch v := data.(type) {
	case map[string]any:
		if currentPart == "*" {
			// Apply to all keys
			for key := range v {
				if len(remainingParts) == 0 {
					v[key] = maskValue(v[key], maskType)
				} else {
					applyMaskingRecursive(v[key], remainingParts, maskType, isArray)
				}
			}
		} else if val, exists := v[currentPart]; exists {
			if len(remainingParts) == 0 {
				// Check if value is an array and isArray flag is set
				if arr, ok := val.([]any); ok && isArray {
					// Mask each element in the array
					for i := range arr {
						arr[i] = maskValue(arr[i], maskType)
					}
					v[currentPart] = arr
				} else {
					v[currentPart] = maskValue(val, maskType)
				}
			} else {
				// Continue traversing
				if arr, ok := val.([]any); ok && isArray {
					// Apply masking to each element in array
					for i := range arr {
						applyMaskingRecursive(arr[i], remainingParts, maskType, isArray)
					}
				} else {
					applyMaskingRecursive(val, remainingParts, maskType, isArray)
				}
			}
		}

	case []any:
		// This handles when we're already inside an array
		for i := range v {
			if len(pathParts) > 0 {
				applyMaskingRecursive(v[i], pathParts, maskType, isArray)
			}
		}
	}
}

func maskValue(value any, maskType MaskingType) any {
	strValue, ok := value.(string)
	if !ok {
		// Try to convert to string
		strValue = toString(value)
	}

	if strValue == "" {
		return value
	}

	switch maskType {
	case MaskingTypeFull:
		return "***"
	case MaskingTypePartial:
		return maskPartial(strValue)
	case MaskingTypeEmail:
		return maskEmail(strValue)
	case MaskingTypeCard:
		return maskCard(strValue)
	default:
		return "***"
	}
}

func maskPartial(s string) string {
	length := len(s)
	if length == 0 {
		return ""
	}
	if length <= 3 {
		return "***"
	}
	if length <= 6 {
		return string(s[0]) + "***"
	}
	return string(s[0]) + strings.Repeat("*", length-2) + string(s[length-1])
}

func maskEmail(email string) string {
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return "***"
	}

	username := parts[0]
	domain := parts[1]

	if len(username) == 0 {
		return "*@" + domain
	}
	if len(username) == 1 {
		return "*@" + domain
	}

	// Mask all characters except the first one, minimum 3 stars
	maskLength := len(username) - 1
	if maskLength < 3 {
		maskLength = 3
	}
	return string(username[0]) + strings.Repeat("*", maskLength) + "@" + domain
}

func maskCard(card string) string {
	// Remove spaces and dashes
	cleaned := strings.ReplaceAll(strings.ReplaceAll(card, " ", ""), "-", "")

	if len(cleaned) < 4 {
		return "****"
	}

	last4 := cleaned[len(cleaned)-4:]
	return "****-****-****-" + last4
}

func toString(value any) string {
	if value == nil {
		return ""
	}

	v := reflect.ValueOf(value)
	switch v.Kind() {
	case reflect.String:
		return v.String()
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return string(rune(v.Int()))
	case reflect.Float32, reflect.Float64:
		return string(rune(int(v.Float())))
	default:
		jsonBytes, _ := json.Marshal(value)
		return string(jsonBytes)
	}
}
