package httpapi

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"strings"
	"unicode/utf8"

	"github.com/fssrepository/myscoutee-registry/internal/protocol"
	"github.com/fssrepository/myscoutee-registry/internal/service"
)

const (
	receiptPathPrefix    = "/v1/mau/batches/"
	receiptPathSuffix    = "/receipt"
	checkpointPathPrefix = "/v1/ledger/checkpoints/"
)

type Options struct {
	MaxRequestBodyBytes int64
	Logger              *slog.Logger
}

type API struct {
	service      *service.Service
	maxBodyBytes int64
	logger       *slog.Logger
}

type errorEnvelope struct {
	Error errorBody `json:"error"`
}

type errorBody struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type healthResponse struct {
	Status          string `json:"status"`
	ProtocolVersion string `json:"protocol_version"`
	RegistryScope   string `json:"registry_scope"`
	RegistryKeyID   string `json:"registry_key_id"`
	LedgerIndex     int64  `json:"ledger_index"`
	EntryCount      int64  `json:"entry_count"`
	LedgerHeadHash  string `json:"ledger_head_hash"`
}

func New(registryService *service.Service, options Options) http.Handler {
	maxBodyBytes := options.MaxRequestBodyBytes
	if maxBodyBytes <= 0 {
		maxBodyBytes = 64 * 1024
	}
	logger := options.Logger
	if logger == nil {
		logger = slog.Default()
	}
	return &API{
		service:      registryService,
		maxBodyBytes: maxBodyBytes,
		logger:       logger,
	}
}

func (api *API) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	response.Header().Set("X-Content-Type-Options", "nosniff")
	defer func() {
		if recovered := recover(); recovered != nil {
			api.logger.Error("panic while serving registry request", "panic", recovered)
			writeError(response, http.StatusInternalServerError, "internal_error", "internal registry error")
		}
	}()

	// Signatures cover the literal protocol path and never cover a query. Do
	// not allow alternate request-target spellings to reach a signed endpoint.
	if request.URL.RawQuery != "" || request.URL.EscapedPath() != request.URL.Path {
		writeError(
			response,
			http.StatusBadRequest,
			"invalid_request_target",
			"request path must be canonical and must not contain a query string",
		)
		return
	}

	switch {
	case request.URL.Path == "/healthz":
		if requireMethod(response, request, http.MethodGet) {
			api.health(response, request)
		}
	case request.URL.Path == protocol.RegistrationPath:
		if requireMethod(response, request, http.MethodPost) {
			api.register(response, request)
		}
	case request.URL.Path == protocol.IdentityPath:
		if requireMethod(response, request, http.MethodGet) {
			api.identity(response, request)
		}
	case request.URL.Path == protocol.BatchPath:
		if requireMethod(response, request, http.MethodPost) {
			api.submitBatch(response, request)
		}
	case strings.HasPrefix(request.URL.Path, receiptPathPrefix) &&
		strings.HasSuffix(request.URL.Path, receiptPathSuffix):
		if requireMethod(response, request, http.MethodGet) {
			api.receipt(response, request)
		}
	case strings.HasPrefix(request.URL.Path, checkpointPathPrefix):
		if requireMethod(response, request, http.MethodGet) {
			api.checkpoint(response, request)
		}
	default:
		writeError(response, http.StatusNotFound, "not_found", "endpoint not found")
	}
}

func (api *API) identity(response http.ResponseWriter, request *http.Request) {
	result, err := api.service.Identity(request.Context())
	if err != nil {
		api.writeServiceError(response, err)
		return
	}
	writeJSON(response, http.StatusOK, result)
}

func (api *API) register(response http.ResponseWriter, request *http.Request) {
	var registration protocol.RegistrationRequest
	if err := api.decodeJSON(response, request, &registration); err != nil {
		api.writeDecodeError(response, err)
		return
	}
	result, err := api.service.RegisterDeployment(request.Context(), registration)
	if err != nil {
		api.writeServiceError(response, err)
		return
	}
	status := http.StatusCreated
	if result.Duplicate {
		status = http.StatusOK
	}
	writeJSON(response, status, result)
}

func (api *API) submitBatch(response http.ResponseWriter, request *http.Request) {
	var batch protocol.BatchRequest
	if err := api.decodeJSON(response, request, &batch); err != nil {
		api.writeDecodeError(response, err)
		return
	}
	result, err := api.service.SubmitBatch(request.Context(), batch)
	if err != nil {
		api.writeServiceError(response, err)
		return
	}
	status := http.StatusCreated
	if result.Duplicate {
		status = http.StatusOK
	}
	writeJSON(response, status, result)
}

func (api *API) receipt(response http.ResponseWriter, request *http.Request) {
	batchID := strings.TrimSuffix(
		strings.TrimPrefix(request.URL.Path, receiptPathPrefix),
		receiptPathSuffix,
	)
	if batchID == "" || strings.Contains(batchID, "/") {
		writeError(response, http.StatusNotFound, "not_found", "endpoint not found")
		return
	}
	result, err := api.service.Receipt(request.Context(), batchID)
	if err != nil {
		api.writeServiceError(response, err)
		return
	}
	writeJSON(response, http.StatusOK, result)
}

func (api *API) checkpoint(response http.ResponseWriter, request *http.Request) {
	date := strings.TrimPrefix(request.URL.Path, checkpointPathPrefix)
	if date == "" || strings.Contains(date, "/") {
		writeError(response, http.StatusNotFound, "not_found", "endpoint not found")
		return
	}
	result, err := api.service.Checkpoint(request.Context(), date)
	if err != nil {
		api.writeServiceError(response, err)
		return
	}
	writeJSON(response, http.StatusOK, result)
}

func (api *API) health(response http.ResponseWriter, request *http.Request) {
	head, err := api.service.Health(request.Context())
	if err != nil {
		api.logger.Error("registry health check failed", "error", err)
		writeError(response, http.StatusServiceUnavailable, "registry_unavailable", "registry storage is unavailable")
		return
	}
	writeJSON(response, http.StatusOK, healthResponse{
		Status:          "ok",
		ProtocolVersion: protocol.Version,
		RegistryScope:   api.service.RegistryScope(),
		RegistryKeyID:   api.service.RegistryKeyID(),
		LedgerIndex:     head.LedgerIndex,
		EntryCount:      head.EntryCount,
		LedgerHeadHash:  head.EntryHash,
	})
}

func (api *API) decodeJSON(
	response http.ResponseWriter,
	request *http.Request,
	destination any,
) error {
	mediaType, parameters, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return errUnsupportedMediaType
	}
	if charset := parameters["charset"]; charset != "" && !strings.EqualFold(charset, "utf-8") {
		return errUnsupportedMediaType
	}
	if request.ContentLength > api.maxBodyBytes {
		return &http.MaxBytesError{Limit: api.maxBodyBytes}
	}
	request.Body = http.MaxBytesReader(response, request.Body, api.maxBodyBytes)
	contents, err := io.ReadAll(request.Body)
	if err != nil {
		return err
	}
	if !utf8.Valid(contents) {
		return errInvalidUTF8
	}
	if err := validateUniqueJSON(contents); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(contents))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return errMultipleJSONValues
		}
		return err
	}
	return nil
}

func validateUniqueJSON(contents []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(contents))
	decoder.UseNumber()
	if err := validateJSONValue(decoder); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		if err == nil {
			return errMultipleJSONValues
		}
		return err
	}
	return nil
}

func validateJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, isDelimiter := token.(json.Delim)
	if !isDelimiter {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("JSON object key is not a string")
			}
			if _, duplicate := seen[key]; duplicate {
				return fmt.Errorf("duplicate JSON key %q", key)
			}
			seen[key] = struct{}{}
			if err := validateJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil {
			return err
		}
		if closing != json.Delim('}') {
			return errors.New("invalid JSON object")
		}
	case '[':
		for decoder.More() {
			if err := validateJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil {
			return err
		}
		if closing != json.Delim(']') {
			return errors.New("invalid JSON array")
		}
	default:
		return errors.New("unexpected JSON delimiter")
	}
	return nil
}

func (api *API) writeDecodeError(response http.ResponseWriter, err error) {
	var maxBytesError *http.MaxBytesError
	switch {
	case errors.Is(err, errUnsupportedMediaType):
		writeError(
			response,
			http.StatusUnsupportedMediaType,
			"unsupported_media_type",
			"Content-Type must be application/json",
		)
	case errors.As(err, &maxBytesError):
		writeError(response, http.StatusRequestEntityTooLarge, "request_too_large", "request body is too large")
	default:
		writeError(response, http.StatusBadRequest, "invalid_json", "request body must contain one valid JSON object")
	}
}

func (api *API) writeServiceError(response http.ResponseWriter, err error) {
	requestError, ok := service.IsRequestError(err)
	if !ok {
		api.logger.Error("registry request failed", "error", err)
		writeError(response, http.StatusInternalServerError, "internal_error", "internal registry error")
		return
	}
	status := requestErrorStatus(requestError.Code)
	writeError(response, status, requestError.Code, requestError.Message)
}

func requestErrorStatus(code string) int {
	switch code {
	case "invalid_signature":
		return http.StatusUnauthorized
	case "deployment_not_found", "receipt_not_found", "checkpoint_not_found":
		return http.StatusNotFound
	case "idempotency_conflict", "replay_conflict", "checkpoint_not_finalized":
		return http.StatusConflict
	case "registry_clock_before_checkpoint",
		"registry_clock_before_ledger_head",
		"registry_clock_before_identity",
		"registry_integrity_unavailable":
		return http.StatusServiceUnavailable
	default:
		return http.StatusBadRequest
	}
}

func requireMethod(response http.ResponseWriter, request *http.Request, expected string) bool {
	if request.Method == expected {
		return true
	}
	response.Header().Set("Allow", expected)
	writeError(response, http.StatusMethodNotAllowed, "method_not_allowed", fmt.Sprintf("method must be %s", expected))
	return false
}

func writeJSON(response http.ResponseWriter, status int, value any) {
	response.Header().Set("Content-Type", "application/json")
	response.WriteHeader(status)
	_ = json.NewEncoder(response).Encode(value)
}

func writeError(response http.ResponseWriter, status int, code, message string) {
	writeJSON(response, status, errorEnvelope{
		Error: errorBody{
			Code:    code,
			Message: message,
		},
	})
}

var (
	errUnsupportedMediaType = errors.New("unsupported media type")
	errMultipleJSONValues   = errors.New("multiple JSON values")
	errInvalidUTF8          = errors.New("JSON body is not valid UTF-8")
)
