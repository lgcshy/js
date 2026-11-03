package errs

import (
	"encoding/json"
	"errors"
)

// BridgeError 表示可安全返回给 CLI 和 MCP 的受控错误，不包含任何秘密或上游原始响应正文。
type BridgeError struct {
	Code           string `json:"error"`
	Message        string `json:"message"`
	ActionRequired bool   `json:"action_required,omitempty"`
	Hint           string `json:"hint,omitempty"`
}

func (e *BridgeError) Error() string {
	if e.Hint != "" {
		return e.Message + "（" + e.Hint + "）"
	}
	return e.Message
}

func New(code, message string) *BridgeError {
	return &BridgeError{Code: code, Message: message}
}

func Action(code, message, hint string) *BridgeError {
	return &BridgeError{
		Code:           code,
		Message:        message,
		ActionRequired: true,
		Hint:           hint,
	}
}

func As(err error) (*BridgeError, bool) {
	var be *BridgeError
	if errors.As(err, &be) {
		return be, true
	}
	return nil, false
}

func (e *BridgeError) Result() map[string]any {
	res := map[string]any{
		"ok":      false,
		"error":   e.Code,
		"message": e.Message,
	}
	if e.ActionRequired {
		res["action_required"] = true
	}
	if e.Hint != "" {
		res["hint"] = e.Hint
	}
	return res
}

func (e *BridgeError) JSON() string {
	b, err := json.Marshal(e.Result())
	if err != nil {
		return `{"ok":false,"error":"LOCAL_ERROR","message":"操作失败"}`
	}
	return string(b)
}
