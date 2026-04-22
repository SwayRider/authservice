// service_clients.go implements service client credential storage.
//
// Service clients are used for service-to-service authentication using the
// OAuth2 client credentials flow. Each client has a unique ID, a hashed secret,
// and a list of scopes defining its permissions.

package db

import (
	"context"
	"database/sql"

	"github.com/lib/pq"
	"github.com/swayrider/authservice/internal/model"
	"github.com/swayrider/swlib/crypto"
	log "github.com/swayrider/swlib/logger"
)

// CreateServiceClient creates a new service client with generated client ID.
// Returns ErrUniqueViolation if a client with the same name already exists.
func (d *DB) CreateServiceClient(
	ctx context.Context,
	name, description string,
	scopes []string,
	secretHash string,
) (clientId string, err error) {
	lg := d.lg.Derive(log.WithFunction("CreateServiceClient"))

	if err = d.checkConnection(); err != nil {
		lg.Errorf("failed to check connection: %v", err)
		return
	}

	clientId, err = crypto.GenerateSecureRandomString(32)
	if err != nil {
		lg.Errorf("failed to generate client id: %v", err)
		return
	}

	_, err = d.ExecContext(ctx, `
		INSERT INTO service_clients
		(name, description, client_id, client_secret, scopes)
		VALUES ($1, $2, $3, $4, $5)
	`, name, description, clientId, secretHash, pq.StringArray(scopes))
	if err != nil {
		if pqErr, ok := err.(*pq.Error); ok {
			if pqErr.Code.Name() == "unique_violation" {
				lg.Errorf("client id already in use: %v", err)
				return "", ErrUniqueViolation
			}
		}
		lg.Errorf("failed to create service client: %v", err)
		return
	}

	return
}

// DeleteServiceClient removes a service client by its client ID.
func (d *DB) DeleteServiceClient(
	ctx context.Context,
	clientId string,
) error {
	lg := d.lg.Derive(log.WithFunction("DeleteServiceClient"))

	if err := d.checkConnection(); err != nil {
		lg.Errorf("failed to check connection: %v", err)
		return err
	}

	_, err := d.ExecContext(ctx, `
		DELETE FROM service_clients
		WHERE client_id = $1
	`, clientId)
	if err != nil {
		lg.Errorf("failed to delete service client: %v", err)
		return err
	}
	return nil
}

// CountServiceClients returns the total number of service clients.
func (d *DB) CountServiceClients(
	ctx context.Context,
) (count int, err error) {
	lg := d.lg.Derive(log.WithFunction("CountServiceClients"))

	if err = d.checkConnection(); err != nil {
		lg.Errorf("failed to check connection: %v", err)
		return
	}

	err = d.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM service_clients
	`).Scan(&count)
	return
}

// ListServiceClients returns a paginated list of service clients.
// If page or pageSize is 0, returns all clients without pagination.
func (d *DB) ListServiceClients(
	ctx context.Context,
	page, pageSize int,
) (clients []model.ServiceClient, err error) {
	var rows *sql.Rows
	if page == 0 || pageSize == 0 {
		rows, err = d.QueryContext(ctx, `
			SELECT client_id, name, description, scopes FROM service_clients
			ORDER BY name
		`)
	} else {
		rows, err = d.QueryContext(ctx, `
			SELECT client_id, name, description, scopes FROM service_clients
			ORDER BY name
			LIMIT $1 OFFSET $2
		`, pageSize, (page-1)*pageSize)
	}
	if err == sql.ErrNoRows {
		return nil, nil
	}
	defer rows.Close()

	for rows.Next() {
		var client model.ServiceClient
		err = rows.Scan(
			&client.ClientID,
			&client.Name,
			&client.Description,
			pq.Array(&client.Scopes),
		)
		if err != nil {
			return nil, err
		}
		clients = append(clients, client)
	}

	return
}

// GetServiceClientByID retrieves a service client with its secret hash for authentication.
// Returns ErrServiceClientNotFound if the client doesn't exist.
func (d *DB) GetServiceClientByID(
	ctx context.Context,
	clientID string,
) (*model.ServiceClientInternal, error) {
	lg := d.lg.Derive(log.WithFunction("GetServiceClientByID"))

	if err := d.checkConnection(); err != nil {
		lg.Errorf("failed to check connection: %v", err)
		return nil, err
	}

	var clnt model.ServiceClientInternal
	err := d.QueryRowContext(ctx, `
		SELECT client_id, client_secret, name, description, scopes FROM service_clients
		WHERE client_id = $1
	`, clientID).Scan(
		&clnt.ClientID,
		&clnt.ClientSecretHash,
		&clnt.Name,
		&clnt.Description,
		pq.Array(&clnt.Scopes),
	)
	if err != nil {
		lg.Errorf("failed to get service client: %v", err)
		return nil, ErrServiceClientNotFound
	}

	return &clnt, nil
}
