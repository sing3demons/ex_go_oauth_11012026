package client

import (
	"context"
)

type ClientService struct {
	repo IClientRepository
}

func NewClientService(repo IClientRepository) *ClientService {
	return &ClientService{
		repo: repo,
	}
}

func (s *ClientService) CreateClient(c context.Context, data *OIDCClient) error {
	return s.repo.InsertClient(c, data)
}

func (s *ClientService) GetClientByID(c context.Context, clientID string) (OIDCClient, error) {
	return s.repo.FindClientByID(c, clientID)
}

// authCode.AuthCode.CodeChallengeMethod, authCode.AuthCode.CodeChallenge
func (s *ClientService) ValidateClientToken(c context.Context, clientID, clientSecret, codeVerifier string) error {
	client, err := s.repo.FindClientByID(c, clientID)
	if err != nil {
		return err
	}

	return client.ValidateToken(clientSecret, codeVerifier)
}
