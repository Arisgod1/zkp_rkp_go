package response

import "github.com/gin-gonic/gin"

type ErrorBody struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	RequestID string `json:"requestId,omitempty"`
}

func JSONError(c *gin.Context, status int, code, msg string) {
	reqID, _ := c.Get("requestId")
	rid, _ := reqID.(string)

	c.JSON(status, ErrorBody{
		Code:      code,
		Message:   msg,
		RequestID: rid,
	})
}

func JSONOK(c *gin.Context, body any) {
	c.JSON(200, body)
}
