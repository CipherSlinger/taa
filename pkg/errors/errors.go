// Package errors 提供通用的带状态码错误封装，支持链式错误原因追踪（Cause/Unwrap），
// 与标准库 errors.Is / errors.As 完全兼容，适用于微服务与 HTTP/RPC 接口统一错误处理。
package errors

import (
	"errors"
	"fmt"
)

// Standard error codes
const (
	CodeOK                  = 0
	CodeUnknown             = 1
	CodeInvalidArgument     = 400
	CodeUnauthorized        = 401
	CodeForbidden           = 403
	CodeNotFound            = 404
	CodeMethodNotAllowed    = 405
	CodeConflict            = 409
	CodeInternal            = 500
	CodeNotImplemented      = 501
	CodeServiceUnavailable  = 503
)

// Error 表示一个包含业务/系统错误码与错误信息的结构体。
type Error struct {
	code    int
	message string
	cause   error
}

// Code 返回错误对应的数值状态码。
func (e *Error) Code() int {
	if e == nil {
		return CodeOK
	}
	return e.code
}

// Message 返回人类可读的错误说明。
func (e *Error) Message() string {
	if e == nil {
		return ""
	}
	return e.message
}

// Cause 返���底层引起该错误的原始 error，若无底层错误则返回 nil。
func (e *Error) Cause() error {
	if e == nil {
		return nil
	}
	return e.cause
}

// Unwrap 实现 Go 1.13+ 标准错误解包接口。
func (e *Error) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.cause
}

// Error 实现 Go 标准 error 接口。
func (e *Error) Error() string {
	if e == nil {
		return ""
	}
	if e.cause != nil {
		return fmt.Sprintf("[%d] %s: %v", e.code, e.message, e.cause)
	}
	return fmt.Sprintf("[%d] %s", e.code, e.message)
}

// New 创建一个新的带状态码错误。
func New(code int, message string) *Error {
	return &Error{
		code:    code,
		message: message,
	}
}

// Errorf 格式化生成一个新的带状态码错误。
func Errorf(code int, format string, args ...any) *Error {
	return &Error{
		code:    code,
		message: fmt.Sprintf(format, args...),
	}
}

// Wrap 包装一个既有错误并附加错误码与上下文描述。
func Wrap(code int, message string, cause error) *Error {
	if cause == nil {
		return &Error{code: code, message: message}
	}
	return &Error{
		code:    code,
		message: message,
		cause:   cause,
	}
}

// Wrapf 格式化包装一个既有错误。
func Wrapf(code int, cause error, format string, args ...any) *Error {
	msg := fmt.Sprintf(format, args...)
	return Wrap(code, msg, cause)
}

// CodeOf 提取任意 error 中的状态码，若错误不属于 *Error 类型则返回 defaultCode 或 CodeInternal。
func CodeOf(err error, defaultCode ...int) int {
	if err == nil {
		return CodeOK
	}
	var coded *Error
	if errors.As(err, &coded) {
		return coded.Code()
	}
	if len(defaultCode) > 0 {
		return defaultCode[0]
	}
	return CodeInternal
}

// Is 包装标准库 errors.Is。
func Is(err, target error) bool {
	return errors.Is(err, target)
}

// As 包装标准库 errors.As。
func As(err error, target any) bool {
	return errors.As(err, target)
}
