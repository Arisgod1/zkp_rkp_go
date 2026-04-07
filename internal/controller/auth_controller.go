package controller

import (
	"github.com/Arisgod1/zkp_rkp_go/pkg/errs"
	"github.com/Arisgod1/zkp_rkp_go/pkg/response"
	"github.com/gin-gonic/gin"

	"github.com/Arisgod1/zkp_rkp_go/internal/model"
	"github.com/Arisgod1/zkp_rkp_go/internal/service"
)

type AuthController struct {
	svc *service.AuthService
}

func NewAuthController(svc *service.AuthService) *AuthController {
	return &AuthController{svc: svc}
}

func (a *AuthController) Register(c *gin.Context) {
	var req model.RegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.JSONError(c, errs.CommonInvalidJSON.Status, errs.CommonInvalidJSON.Code, errs.CommonInvalidJSON.Message)
		return
	}

	// 细粒度验证每个必填字段
	if req.Username == "" {
		response.JSONError(c, errs.AuthRegisterUsernameEmpty.Status, errs.AuthRegisterUsernameEmpty.Code, errs.AuthRegisterUsernameEmpty.Message)
		return
	}
	if req.PublicKeyY == "" {
		response.JSONError(c, errs.AuthRegisterPublicKeyEmpty.Status, errs.AuthRegisterPublicKeyEmpty.Code, errs.AuthRegisterPublicKeyEmpty.Message)
		return
	}
	if req.Salt == "" {
		response.JSONError(c, errs.AuthRegisterSaltEmpty.Status, errs.AuthRegisterSaltEmpty.Code, errs.AuthRegisterSaltEmpty.Message)
		return
	}

	if err := a.svc.Register(c.Request.Context(), req); err != nil {
		// 映射 service 错误到标准错误码
		errInfo := errs.MapServiceErrorToCode(err.Error())

		// 根据错误码进一步细化（必要时）
		switch err.Error() {
		case "username already exists":
			errInfo = errs.AuthRegisterUsernameExists
		default:
			errInfo = errs.AuthRegisterDBWriteFailed
		}

		response.JSONError(c, errInfo.Status, errInfo.Code, errInfo.Message)
		return
	}

	response.JSONOK(c, gin.H{
		"username": req.Username,
		"message":  "User registered successfully",
	})
}

func (a *AuthController) Challenge(c *gin.Context) {
	var req model.ChallengeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.JSONError(c, errs.CommonInvalidJSON.Status, errs.CommonInvalidJSON.Code, errs.CommonInvalidJSON.Message)
		return
	}

	// 细粒度验证每个必填字段
	if req.Username == "" {
		response.JSONError(c, errs.AuthChallengeUsernameEmpty.Status, errs.AuthChallengeUsernameEmpty.Code, errs.AuthChallengeUsernameEmpty.Message)
		return
	}
	if req.ClientR == "" {
		response.JSONError(c, errs.AuthChallengeClientREmpty.Status, errs.AuthChallengeClientREmpty.Code, errs.AuthChallengeClientREmpty.Message)
		return
	}

	resp, err := a.svc.Challenge(c.Request.Context(), req)
	if err != nil {
		// 映射 service 错误到标准错误码
		errInfo := errs.MapServiceErrorToCode(err.Error())
		if errInfo == errs.CommonInternalError {
			errInfo = errs.AuthChallengeCacheWriteFailed
		}
		response.JSONError(c, errInfo.Status, errInfo.Code, errInfo.Message)
		return
	}

	response.JSONOK(c, resp)
}

func (a *AuthController) Verify(c *gin.Context) {
	var req model.VerifyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.JSONError(c, errs.CommonInvalidJSON.Status, errs.CommonInvalidJSON.Code, errs.CommonInvalidJSON.Message)
		return
	}

	// 细粒度验证每个必填字段
	if req.ChallengeID == "" {
		response.JSONError(c, errs.AuthVerifyChallengeIDEmpty.Status, errs.AuthVerifyChallengeIDEmpty.Code, errs.AuthVerifyChallengeIDEmpty.Message)
		return
	}
	if req.S == "" {
		response.JSONError(c, errs.AuthVerifySEmpty.Status, errs.AuthVerifySEmpty.Code, errs.AuthVerifySEmpty.Message)
		return
	}
	if req.ClientR == "" {
		response.JSONError(c, errs.AuthVerifyClientREmpty.Status, errs.AuthVerifyClientREmpty.Code, errs.AuthVerifyClientREmpty.Message)
		return
	}
	if req.Username == "" {
		response.JSONError(c, errs.AuthVerifyUsernameEmpty.Status, errs.AuthVerifyUsernameEmpty.Code, errs.AuthVerifyUsernameEmpty.Message)
		return
	}

	token, err := a.svc.Verify(c.Request.Context(), req)
	if err != nil {
		// 映射 service 错误到标准错误码
		errInfo := errs.MapServiceErrorToCode(err.Error())
		response.JSONError(c, errInfo.Status, errInfo.Code, errInfo.Message)
		return
	}

	response.JSONOK(c, gin.H{
		"token":     token,
		"type":      "Bearer",
		"expiresIn": 86400,
	})
}
