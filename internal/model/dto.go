package model

type RegisterRequest struct {
	Username   string `json:"username"`
	PublicKeyY string `json:"publicKeyY"`
	Salt       string `json:"salt"`
}

type ChallengeRequest struct {
	Username string `json:"username"`
	ClientR  string `json:"clientR"`
}
type ChallengeCache struct {
	Username  string `json:"username"`
	ClientR   string `json:"clientR"`
	Challenge string `json:"challenge"`
	CreatedAt int64  `json:"createdAt"`
}
type VerifyRequest struct {
	ChallengeID string `json:"challengeId"`
	S           string `json:"s"`
	ClientR     string `json:"clientR"`
	Username    string `json:"username"`
}
