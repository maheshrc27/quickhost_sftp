package main

import (
	"log"
	"path/filepath"

	"github.com/pterodactyl/sftp-server/sftp_server"
)

const (
	BASE_PATH    = "/app_data/sftp"
	BIND_ADDRESS = "0.0.0.0"
)

func main() {
	server := &sftp_server.Server{Settings: sftp_server.Settings{BasePath: BASE_PATH, ReadOnly: false, BindPort: 2022, BindAddress: BIND_ADDRESS}, User: sftp_server.SftpUser{Uid: 1000, Gid: 1000}}
	// Initialize the server
	if err := sftp_server.New(server); err != nil {
		log.Fatal(err)
	}

	// Configure path validator
	server.PathValidator = func(fs sftp_server.FileSystem, p string) (string, error) {
		cleanPath := filepath.Clean(p)
		return filepath.Join(server.Settings.BasePath, cleanPath), nil
	}

	// Configure disk space validator
	server.DiskSpaceValidator = func(fs sftp_server.FileSystem) bool {
		// Implement your disk space validation logic
		return true
	}

	// Configure credential validator
	server.CredentialValidator = func(r sftp_server.AuthenticationRequest) (*sftp_server.AuthenticationResponse, error) {

		dir, err := sftp_server.AutheticateUser(r.User, r.Pass)
		if err != nil {
			return nil, &sftp_server.InvalidCredentialsError{}
		}

		server.Settings.BasePath = "/app_data/" + dir

		return &sftp_server.AuthenticationResponse{
			Server: "sftp",
			Token:  "your-auth-token",
			Permissions: []string{
				sftp_server.PermissionFileRead,
				sftp_server.PermissionFileReadContent,
				sftp_server.PermissionFileCreate,
				sftp_server.PermissionFileUpdate,
				sftp_server.PermissionFileDelete,
			},
		}, nil
	}

	// Start the server (this will block)
	if err := server.Initialize(); err != nil {
		log.Fatal(err)
	}
}
