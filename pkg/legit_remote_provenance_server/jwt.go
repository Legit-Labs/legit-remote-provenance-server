package legit_remote_provenance_server

import (
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/MicahParks/keyfunc"
	"github.com/golang-jwt/jwt/v4"
)

const (
	GITHUB_JWKS             = "https://token.actions.githubusercontent.com/.well-known/jwks"
	LEGIT_PROVENANCE_ACTION = "legit-labs/legit-provenance-action"
)

type JwtVerifier interface {
	Verify(jwtB64 string) error
}

type jwtVerifier struct {
	verifyToken bool
	jkwsAddr    string
	workflowRef string
}

func NewJwtVerifier(verifyToken bool) JwtVerifier {
	return &jwtVerifier{
		verifyToken: verifyToken,
		jkwsAddr:    GITHUB_JWKS,
		workflowRef: LEGIT_PROVENANCE_ACTION,
	}
}

func (v *jwtVerifier) Verify(jwtB64 string) error {
	token, err := v.parseToken(jwtB64)
	if err != nil {
		return err
	}

	if v.verifyToken && !token.Valid {
		return fmt.Errorf("the JWT is not valid.")
	}

	err = v.verifyClaims(token)
	if err != nil {
		return err
	}

	return nil
}

func getJwks() (*keyfunc.JWKS, error) {
	resp, err := http.Get(GITHUB_JWKS)
	if err != nil {
		return nil, fmt.Errorf("failed to get GitHub's JKWS: %v", err)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read GitHub's JKWS from response: %v", err)
	}

	// Create the JWKS from the resource at the given URL.
	jwks, err := keyfunc.NewJSON(body)
	if err != nil {
		return nil, fmt.Errorf("Failed to create JWKS from resource at the given URL: %v", err)
	}

	return jwks, nil
}

func (v *jwtVerifier) parseToken(jwtB64 string) (*jwt.Token, error) {
	// Get GitHub's JKWS for parsing
	jwks, err := getJwks()
	if err != nil {
		return nil, fmt.Errorf("Failed to get JWKS for JWT parsing: %v", err)
	}

	// Parse the JWT
	token, err := jwt.Parse(jwtB64, jwks.Keyfunc)
	if err != nil {
		return nil, fmt.Errorf("Failed to parse the JWT: %v", err)
	}

	return token, nil
}

func (v *jwtVerifier) verifyJobWorkflowRef(claims jwt.MapClaims) error {
	_jobWFRef, exist := claims["job_workflow_ref"]
	if !exist {
		return fmt.Errorf("missing job workflow ref")
	}

	jobWFRef, ok := _jobWFRef.(string)
	if !ok {
		return fmt.Errorf("failed to parse job workflow ref")
	}

	if jobWFRef != v.workflowRef {
		return fmt.Errorf("invalid job workflow ref: %v != %v", jobWFRef, v.workflowRef)
	}

	return nil
}

func (v *jwtVerifier) verifyClaims(token *jwt.Token) error {
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return fmt.Errorf("failed to parse claims")
	}

	err := v.verifyJobWorkflowRef(claims)
	if err != nil {
		return fmt.Errorf("failed to verify job workflow ref cliam: %v", err)
	}

	return nil
}
