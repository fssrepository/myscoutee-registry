package service

import "fmt"

type RequestError struct {
	Code    string
	Message string
}

func (err *RequestError) Error() string {
	return fmt.Sprintf("%s: %s", err.Code, err.Message)
}

func requestError(code, message string) error {
	return &RequestError{Code: code, Message: message}
}
