package client

import "context"

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
