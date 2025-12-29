package auth

import (
	"testing"
	"time"

	"github.com/google/uuid"
)


func TestJWT(t *testing.T){
	// 1. Setup test data
	secret := "super-secret-key"
	userID := uuid.New()
	expiry := time.Hour // 1 hour from now

	// 2. Test successful creation and validation
	token, err := MakeJWT(userID,secret,expiry)
	if err != nil {
		t.Fatalf("Failed to make JWT: %v", err)
	}

	validatedID, err := ValidateJWT(token,secret)
	if err != nil {
		t.Errorf("Validation failed: %v", err)
	}

	if validatedID != userID {
		t.Errorf("Expected userID %v, got %v", userID,validatedID)
	}

	// 3. Test expiration logic
	expiredToken, err := MakeJWT(userID,secret, -time.Hour)
	if err != nil {
		t.Fatalf("Failed to make expired JWT:%v",err)
	}

	_,err = ValidateJWT(expiredToken,secret)
	if err == nil {
		t.Errorf("Validation should have failed for expired token")
	}
}
