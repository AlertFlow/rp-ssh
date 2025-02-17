package main

import (
	"errors"
	"net/rpc"
	"strconv"
	"strings"
	"time"

	"github.com/AlertFlow/runner/pkg/executions"
	"github.com/AlertFlow/runner/pkg/plugins"
	"github.com/melbahja/goph"
	"golang.org/x/crypto/ssh"

	"github.com/v1Flows/alertFlow/services/backend/pkg/models"

	"github.com/hashicorp/go-plugin"
)

// Plugin is an implementation of the Plugin interface
type Plugin struct{}

// ifEmpty returns the defaultValue if the input is an empty string, otherwise it returns the input.
func ifEmpty(input, defaultValue string) string {
	if input == "" {
		return defaultValue
	}
	return input
}

func (p *Plugin) ExecuteTask(request plugins.ExecuteTaskRequest) (plugins.Response, error) {
	err := executions.UpdateStep(request.Config, request.Execution.ID.String(), models.ExecutionSteps{
		ID:        request.Step.ID,
		Messages:  []string{"Starting action"},
		Status:    "running",
		StartedAt: time.Now(),
	})
	if err != nil {
		return plugins.Response{
			Success: false,
		}, err
	}

	var target string
	var port uint
	var username string
	var password string
	var privateKeyFile string
	var privateKeyFilePassword string
	var useSSHAgent bool
	var commands []string

	// access action params
	for _, param := range request.Step.Action.Params {
		if param.Key == "Target" {
			target = param.Value
		}
		if param.Key == "Port" {
			portInt, _ := strconv.ParseUint(param.Value, 10, 16)
			port = uint(portInt)
		}
		if param.Key == "Username" {
			username = param.Value
		}
		if param.Key == "Password" {
			password = param.Value
		}
		if param.Key == "PrivateKeyFile" {
			privateKeyFile = param.Value
		}
		if param.Key == "PrivateKeyFilePassword" {
			privateKeyFilePassword = param.Value
		}
		if param.Key == "UseSSHAgent" {
			useSSHAgent = strings.ToLower(param.Value) == "true"
		}
		if param.Key == "Commands" {
			commands = strings.Split(param.Value, "\n")
		}
	}

	var auth goph.Auth

	// use private key file if provided
	if privateKeyFile != "" {
		auth, err = goph.Key(privateKeyFile, ifEmpty(privateKeyFilePassword, ""))
		if err != nil {
			return plugins.Response{
				Success: false,
			}, err
		}

		err := executions.UpdateStep(request.Config, request.Execution.ID.String(), models.ExecutionSteps{
			ID:       request.Step.ID,
			Messages: []string{"Use private key file to authenticate"},
		})
		if err != nil {
			return plugins.Response{
				Success: false,
			}, err
		}
	}

	if useSSHAgent {
		auth, err = goph.UseAgent()
		if err != nil {
			return plugins.Response{
				Success: false,
			}, err
		}

		err := executions.UpdateStep(request.Config, request.Execution.ID.String(), models.ExecutionSteps{
			ID:       request.Step.ID,
			Messages: []string{"Use ssh agent to authenticate"},
		})
		if err != nil {
			return plugins.Response{
				Success: false,
			}, err
		}
	}

	// use password if provided
	if password != "" {
		auth = goph.Password(password)

		err := executions.UpdateStep(request.Config, request.Execution.ID.String(), models.ExecutionSteps{
			ID:       request.Step.ID,
			Messages: []string{"Use password to authenticate"},
		})
		if err != nil {
			return plugins.Response{
				Success: false,
			}, err
		}
	}

	err = executions.UpdateStep(request.Config, request.Execution.ID.String(), models.ExecutionSteps{
		ID:       request.Step.ID,
		Messages: []string{"Connecting to remote server " + target + " as " + username},
	})
	if err != nil {
		return plugins.Response{
			Success: false,
		}, err
	}

	client, err := goph.NewConn(&goph.Config{
		User:     username,
		Addr:     target,
		Port:     port,
		Auth:     auth,
		Timeout:  goph.DefaultTimeout,
		Callback: ssh.InsecureIgnoreHostKey(),
	})
	if err != nil {
		err := executions.UpdateStep(request.Config, request.Execution.ID.String(), models.ExecutionSteps{
			ID: request.Step.ID,
			Messages: []string{
				"Failed to connect to remote server " + target + " as " + username,
				err.Error(),
			},
			Status:     "error",
			FinishedAt: time.Now(),
		})
		if err != nil {
			return plugins.Response{
				Success: false,
			}, err
		}

		return plugins.Response{
			Success: false,
		}, err
	}

	// Defer closing the network connection.
	defer client.Close()

	for _, command := range commands {
		// Execute your command.
		out, err := client.Run(command)
		if err != nil {
			err := executions.UpdateStep(request.Config, request.Execution.ID.String(), models.ExecutionSteps{
				ID: request.Step.ID,
				Messages: []string{
					"Failed to execute command: " + command,
					err.Error(),
				},
				Status:     "error",
				FinishedAt: time.Now(),
			})
			if err != nil {
				return plugins.Response{
					Success: false,
				}, err
			}

			return plugins.Response{
				Success: false,
			}, err
		}

		err = executions.UpdateStep(request.Config, request.Execution.ID.String(), models.ExecutionSteps{
			ID:       request.Step.ID,
			Messages: []string{string(out)},
		})
		if err != nil {
			return plugins.Response{
				Success: false,
			}, err
		}
	}

	err = executions.UpdateStep(request.Config, request.Execution.ID.String(), models.ExecutionSteps{
		ID:         request.Step.ID,
		Messages:   []string{"Finished ssh action"},
		Status:     "success",
		FinishedAt: time.Now(),
	})
	if err != nil {
		return plugins.Response{
			Success: false,
		}, err
	}

	return plugins.Response{
		Success: true,
	}, nil
}

func (p *Plugin) HandlePayload(request plugins.PayloadHandlerRequest) (plugins.Response, error) {
	return plugins.Response{
		Success: false,
	}, errors.New("not implemented")
}

func (p *Plugin) Info() (models.Plugins, error) {
	var plugin = models.Plugins{
		Name:    "SSH",
		Type:    "action",
		Version: "1.1.0",
		Author:  "JustNZ",
		Actions: models.Actions{
			Name:        "SSH",
			Description: "Connect to a remote server using SSH and execute commands",
			Plugin:      "ssh",
			Icon:        "solar:server-path-linear",
			Category:    "Utility",
			Params: []models.Params{
				{
					Key:         "Target",
					Type:        "text",
					Default:     "",
					Required:    true,
					Description: "The target server IP address or hostname",
				},
				{
					Key:         "Port",
					Type:        "number",
					Default:     "22",
					Required:    true,
					Description: "The target server port",
				},
				{
					Key:         "Username",
					Type:        "text",
					Default:     "",
					Required:    true,
					Description: "The username to authenticate with",
				},
				{
					Key:         "Password",
					Type:        "password",
					Default:     "",
					Required:    false,
					Description: "The password to authenticate with.",
				},
				{
					Key:         "UseSSHAgent",
					Type:        "boolean",
					Default:     "false",
					Required:    false,
					Description: "Use the SSH agent to authenticate.",
				},
				{
					Key:         "PrivateKeyFile",
					Type:        "text",
					Default:     "",
					Required:    false,
					Description: "The private key file path to authenticate with. This path must be accessible by the runner.",
				},
				{
					Key:         "PrivateKeyFilePassword",
					Type:        "password",
					Default:     "",
					Required:    false,
					Description: "The password to decrypt the private key file.",
				},
				{
					Key:         "Commands",
					Type:        "textarea",
					Default:     "",
					Required:    true,
					Description: "The commands to execute on the remote server. Each command should be on a new line.",
				},
			},
		},
		Endpoints: models.PayloadEndpoints{},
	}

	return plugin, nil
}

// PluginRPCServer is the RPC server for Plugin
type PluginRPCServer struct {
	Impl plugins.Plugin
}

func (s *PluginRPCServer) ExecuteTask(request plugins.ExecuteTaskRequest, resp *plugins.Response) error {
	result, err := s.Impl.ExecuteTask(request)
	*resp = result
	return err
}

func (s *PluginRPCServer) HandlePayload(request plugins.PayloadHandlerRequest, resp *plugins.Response) error {
	result, err := s.Impl.HandlePayload(request)
	*resp = result
	return err
}

func (s *PluginRPCServer) Info(args interface{}, resp *models.Plugins) error {
	result, err := s.Impl.Info()
	*resp = result
	return err
}

// PluginServer is the implementation of plugin.Plugin interface
type PluginServer struct {
	Impl plugins.Plugin
}

func (p *PluginServer) Server(*plugin.MuxBroker) (interface{}, error) {
	return &PluginRPCServer{Impl: p.Impl}, nil
}

func (p *PluginServer) Client(b *plugin.MuxBroker, c *rpc.Client) (interface{}, error) {
	return &plugins.PluginRPC{Client: c}, nil
}

func main() {
	plugin.Serve(&plugin.ServeConfig{
		HandshakeConfig: plugin.HandshakeConfig{
			ProtocolVersion:  1,
			MagicCookieKey:   "PLUGIN_MAGIC_COOKIE",
			MagicCookieValue: "hello",
		},
		Plugins: map[string]plugin.Plugin{
			"plugin": &PluginServer{Impl: &Plugin{}},
		},
		GRPCServer: plugin.DefaultGRPCServer,
	})
}
