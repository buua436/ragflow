package handler

import (
	"encoding/json"
	"net/http/httptest"
	"testing"

	"ragflow/internal/common"
	"ragflow/internal/permission"

	"github.com/gin-gonic/gin"
)

func TestRespondFileServiceError(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for _, tc := range []struct {
		name string
		err  error
		code int
		msg  string
	}{
		{"authorization", permission.ErrPermissionDenied, int(common.CodeNotFound), "Resource not found"},
		{"identity mismatch", permission.ErrIdentityMismatch, int(common.CodeNotFound), "Resource not found"},
		{"invalid permission request", permission.ErrInvalidPermission, int(common.CodeBadRequest), "Invalid permission request"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			respondFileServiceError(c, tc.err)
			if w.Code != 200 {
				t.Fatalf("HTTP status = %d, want 200", w.Code)
			}
			var body struct {
				Code    int    `json:"code"`
				Message string `json:"message"`
			}
			if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil || body.Code != tc.code || body.Message != tc.msg {
				t.Fatalf("body = %s, want code=%d message=%q", w.Body, tc.code, tc.msg)
			}
		})
	}

	for _, test := range []struct {
		name string
		err  error
		code common.ErrorCode
	}{
		{name: "identity mismatch", err: permission.ErrIdentityMismatch, code: common.CodeForbidden},
		{name: "invalid permission request", err: permission.ErrInvalidPermission, code: common.CodeBadRequest},
	} {
		t.Run("link code/"+test.name, func(t *testing.T) {
			if code := linkToDatasetsErrorCode(test.err); code != test.code {
				t.Fatalf("linkToDatasetsErrorCode() = %d, want %d", code, test.code)
			}
		})
	}
}
