package errs

import "net/http"

// ErrorInfo 定义错误码、HTTP状态、和描述
type ErrorInfo struct {
	Code    string
	Status  int
	Message string
}

// ============ COMMON（通用错误）============
var (
	CommonInvalidJSON      = ErrorInfo{"COMMON_INVALID_JSON", http.StatusBadRequest, "invalid json format"}
	CommonValidationFailed = ErrorInfo{"COMMON_VALIDATION_FAILED", http.StatusBadRequest, "validation failed"}
	CommonInternalError    = ErrorInfo{"COMMON_INTERNAL_ERROR", http.StatusInternalServerError, "internal server error"}
	CommonRateLimited      = ErrorInfo{"COMMON_RATE_LIMITED", http.StatusTooManyRequests, "rate limited"}
	CommonUnsupportedMedia = ErrorInfo{"COMMON_UNSUPPORTED_MEDIA_TYPE", http.StatusUnsupportedMediaType, "unsupported media type"}
)

// ============ AUTH_REGISTER（注册错误）============
var (
	AuthRegisterUsernameEmpty  = ErrorInfo{"AUTH_REGISTER_USERNAME_EMPTY", http.StatusBadRequest, "username cannot be empty"}
	AuthRegisterPublicKeyEmpty = ErrorInfo{"AUTH_REGISTER_PUBLIC_KEY_EMPTY", http.StatusBadRequest, "public key cannot be empty"}
	AuthRegisterSaltEmpty      = ErrorInfo{"AUTH_REGISTER_SALT_EMPTY", http.StatusBadRequest, "salt cannot be empty"}
	AuthRegisterUsernameExists = ErrorInfo{"AUTH_REGISTER_USERNAME_EXISTS", http.StatusConflict, "username already exists"}
	AuthRegisterDBWriteFailed  = ErrorInfo{"AUTH_REGISTER_DB_WRITE_FAILED", http.StatusInternalServerError, "failed to write user to database"}
)

// ============ AUTH_CHALLENGE（挑战阶段错误）============
var (
	AuthChallengeUsernameEmpty    = ErrorInfo{"AUTH_CHALLENGE_USERNAME_EMPTY", http.StatusBadRequest, "username cannot be empty"}
	AuthChallengeClientREmpty     = ErrorInfo{"AUTH_CHALLENGE_CLIENT_R_EMPTY", http.StatusBadRequest, "clientR cannot be empty"}
	AuthChallengeCacheWriteFailed = ErrorInfo{"AUTH_CHALLENGE_CACHE_WRITE_FAILED", http.StatusInternalServerError, "failed to cache challenge"}
)

// ============ AUTH_VERIFY（验证阶段错误）============
var (
	AuthVerifyChallengeIDEmpty     = ErrorInfo{"AUTH_VERIFY_CHALLENGE_ID_EMPTY", http.StatusBadRequest, "challengeId cannot be empty"}
	AuthVerifySEmpty               = ErrorInfo{"AUTH_VERIFY_S_EMPTY", http.StatusBadRequest, "s cannot be empty"}
	AuthVerifyClientREmpty         = ErrorInfo{"AUTH_VERIFY_CLIENT_R_EMPTY", http.StatusBadRequest, "clientR cannot be empty"}
	AuthVerifyUsernameEmpty        = ErrorInfo{"AUTH_VERIFY_USERNAME_EMPTY", http.StatusBadRequest, "username cannot be empty"}
	AuthVerifyChallengeNotFound    = ErrorInfo{"AUTH_VERIFY_CHALLENGE_NOT_FOUND", http.StatusUnauthorized, "challenge not found or expired"}
	AuthVerifyChallengeParseFailed = ErrorInfo{"AUTH_VERIFY_CHALLENGE_PARSE_FAILED", http.StatusInternalServerError, "challenge deserialization failed"}
	AuthVerifyChallengeMismatch    = ErrorInfo{"AUTH_VERIFY_CHALLENGE_MISMATCH", http.StatusUnauthorized, "challenge mismatch: username or clientR does not match cache"}
	AuthVerifyInvalidCredential    = ErrorInfo{"AUTH_VERIFY_INVALID_CREDENTIAL", http.StatusUnauthorized, "user not found or invalid credential"}
	AuthVerifyChallengeInvalid     = ErrorInfo{"AUTH_VERIFY_CHALLENGE_INVALID", http.StatusUnauthorized, "recomputed challenge does not match"}
	AuthVerifyInvalidSHex          = ErrorInfo{"AUTH_VERIFY_INVALID_S_HEX", http.StatusBadRequest, "s is not a valid hex string"}
	AuthVerifyInvalidClientRHex    = ErrorInfo{"AUTH_VERIFY_INVALID_CLIENT_R_HEX", http.StatusBadRequest, "clientR is not a valid hex string"}
	AuthVerifyInvalidPublicKeyHex  = ErrorInfo{"AUTH_VERIFY_INVALID_PUBLIC_KEY_HEX", http.StatusBadRequest, "publicKeyY is not a valid hex string"}
	AuthVerifyInvalidChallengeHex  = ErrorInfo{"AUTH_VERIFY_INVALID_CHALLENGE_HEX", http.StatusInternalServerError, "challenge is not a valid hex string (server data corrupted)"}
	AuthVerifyZKPFailed            = ErrorInfo{"AUTH_VERIFY_ZKP_FAILED", http.StatusUnauthorized, "zkp verification failed"}
	AuthVerifyTokenIssueFailed     = ErrorInfo{"AUTH_VERIFY_TOKEN_ISSUE_FAILED", http.StatusInternalServerError, "failed to issue JWT token"}
)

// ============ AUTH_TOKEN（Token错误）============
var (
	AuthTokenMissing        = ErrorInfo{"AUTH_TOKEN_MISSING", http.StatusUnauthorized, "authorization token missing"}
	AuthTokenInvalid        = ErrorInfo{"AUTH_TOKEN_INVALID", http.StatusUnauthorized, "invalid or expired token"}
	AuthTokenSubjectMissing = ErrorInfo{"AUTH_TOKEN_SUBJECT_MISSING", http.StatusUnauthorized, "token subject (sub) is missing"}
)

// ============ INFRA（基础设施错误）============
var (
	InfraRedisUnavailable = ErrorInfo{"INFRA_REDIS_UNAVAILABLE", http.StatusServiceUnavailable, "redis service unavailable"}
	InfraDBUnavailable    = ErrorInfo{"INFRA_DB_UNAVAILABLE", http.StatusServiceUnavailable, "database service unavailable"}
)

// MapServiceErrorToCode 将 service 返回的错误消息映射到标准错误码
// 这是一个简单的映射层，未来可考虑使用自定义错误类型替代
func MapServiceErrorToCode(errMsg string) ErrorInfo {
	switch errMsg {
	// Register 错误映射
	case "username/publicKeyY/salt cannot be empty":
		// 需要在 controller 层更细粒度地检查
		return AuthRegisterUsernameEmpty
	case "username already exists":
		return AuthRegisterUsernameExists
	// Challenge 错误映射
	case "username/clientR cannot be empty":
		// 需要在 controller 层更细粒度地检查
		return AuthChallengeUsernameEmpty
	case "failed to cache challenge":
		return AuthChallengeCacheWriteFailed
	// Verify 错误映射
	case "challengeId/s/clientR/username cannot be empty":
		// 需要在 controller 层更细粒度地检查
		return AuthVerifyChallengeIDEmpty
	case "challenge not found or expired":
		return AuthVerifyChallengeNotFound
	case "challenge parse failed":
		return AuthVerifyChallengeParseFailed
	case "challenge mismatch":
		return AuthVerifyChallengeMismatch
	case "invalid credential":
		return AuthVerifyInvalidCredential
	case "challenge invalid":
		return AuthVerifyChallengeInvalid
	case "invalid s":
		return AuthVerifyInvalidSHex
	case "invalid clientR":
		return AuthVerifyInvalidClientRHex
	case "invalid publicKeyY":
		return AuthVerifyInvalidPublicKeyHex
	case "invalid challenge c":
		return AuthVerifyInvalidChallengeHex
	case "zkp verification failed":
		return AuthVerifyZKPFailed
	case "token create failed":
		return AuthVerifyTokenIssueFailed
	default:
		return CommonInternalError
	}
}
