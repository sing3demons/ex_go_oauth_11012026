package logAction

import "strings"

const (
	Consuming    = "[CONSUMING]"
	Producing    = "[PRODUCING]"
	AppLogic     = "[APP_LOGIC]"
	HttpRequest  = "[HTTP_REQUEST]"
	HttpResponse = "[HTTP_RESPONSE]"
	DbRequest    = "[DB_REQUEST]"
	DbResponse   = "[DB_RESPONSE]"
	Exception    = "[EXCEPTION]"
	Inbound      = "[INBOUND]"
	Outbound     = "[OUTBOUND]"
	System       = "[SYSTEM]"
	Produced     = "[PRODUCED]"
)

type DBActionEnum string

const (
	DB_CREATE DBActionEnum = "CREATE"
	DB_READ   DBActionEnum = "READ"
	DB_UPDATE DBActionEnum = "UPDATE"
	DB_DELETE DBActionEnum = "DELETE"
	DB_NONE   DBActionEnum = "NONE"
)

type LoggerAction struct {
	Action            string `json:"action"`
	ActionDescription string `json:"actionDescription"`
	SubAction         string `json:"subAction,omitempty"`
}

func CONSUMING(desc string, subAction ...string) LoggerAction {
	return LoggerAction{
		Action:            Consuming,
		ActionDescription: desc,
		SubAction:         strings.Join(subAction, ", "),
	}
}

func PRODUCING(desc string, subAction ...string) LoggerAction {
	return LoggerAction{
		Action:            Producing,
		ActionDescription: desc,
		SubAction:         strings.Join(subAction, ", "),
	}
}

func INBOUND(desc string, subAction ...string) LoggerAction {
	return LoggerAction{
		Action:            Inbound,
		ActionDescription: desc,
		SubAction:         strings.Join(subAction, ", "),
	}
}

func OUTBOUND(desc string, subAction ...string) LoggerAction {
	return LoggerAction{
		Action:            Outbound,
		ActionDescription: desc,
		SubAction:         strings.Join(subAction, ", "),
	}
}

func APP_LOGIC(desc string, subAction ...string) LoggerAction {
	return LoggerAction{
		Action:            AppLogic,
		ActionDescription: desc,
		SubAction:         strings.Join(subAction, ", "),
	}
}

func HTTP_REQUEST(desc string, subAction ...string) LoggerAction {
	return LoggerAction{
		Action:            HttpRequest,
		ActionDescription: desc,
		SubAction:         strings.Join(subAction, ", "),
	}
}

func HTTP_RESPONSE(desc string, subAction ...string) LoggerAction {
	return LoggerAction{
		Action:            HttpResponse,
		ActionDescription: desc,
		SubAction:         strings.Join(subAction, ", "),
	}
}

func DB_REQUEST(operation DBActionEnum, subAction string) LoggerAction {
	return LoggerAction{
		Action:            DbRequest,
		ActionDescription: subAction,
		SubAction:         string(operation),
	}
}

func DB_RESPONSE(operation DBActionEnum, subAction string) LoggerAction {
	return LoggerAction{
		Action:            DbResponse,
		ActionDescription: subAction,
		SubAction:         string(operation),
	}
}

func EXCEPTION(desc string, subAction ...string) LoggerAction {
	return LoggerAction{
		Action:            Exception,
		ActionDescription: desc,
		SubAction:         strings.Join(subAction, ", "),
	}
}

func SYSTEM(desc string, subAction ...string) LoggerAction {
	return LoggerAction{
		Action:            System,
		ActionDescription: desc,
		SubAction:         strings.Join(subAction, ", "),
	}
}

func PRODUCED(desc string, subAction ...string) LoggerAction {
	return LoggerAction{
		Action:            Produced,
		ActionDescription: desc,
		SubAction:         strings.Join(subAction, ", "),
	}
}
