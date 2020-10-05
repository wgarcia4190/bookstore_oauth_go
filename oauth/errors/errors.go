package errors

import (
	"errors"
	"fmt"
	"net/http"
)

type RestErr struct {
	Message string `json:"message"`
	Status  int    `json:"status"`
	Err     string `json:"error"`
}

func (r *RestErr) Error() string {
	return r.Err
}

func NewError(msg string) error {
	return errors.New(msg)
}

func NewBadRequestError(message string, flags ...interface{}) *RestErr {
	return &RestErr{
		Message: fmt.Sprintf(message, flags...),
		Status:  http.StatusBadRequest,
		Err:     "bad_request",
	}
}

func NewNotFoundError(message string, flags ...interface{}) *RestErr {
	return &RestErr{
		Message: fmt.Sprintf(message, flags...),
		Status:  http.StatusNotFound,
		Err:     "not_found",
	}
}

func NewInternalServerError(message string, flags ...interface{}) *RestErr {
	return &RestErr{
		Message: fmt.Sprintf(message, flags...),
		Status:  http.StatusInternalServerError,
		Err:     "internal_server_error",
	}
}
