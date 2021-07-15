package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/tekkamanendless/iaqualink"
)

// Config is the config for the application.
type Config struct {
	Username            string `json:"username"`
	Password            string `json:"password"`
	AuthenticationToken string `json:"authentication_token"`
	UserID              string `json:"user_id"`
}

func main() {
	rootCmd := &cobra.Command{
		Use:   "iaqualink",
		Short: "iAquaLink client",
		Long:  `This communicates with an iAquaLink device.`,
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			if value, _ := cmd.Flags().GetString("log-level"); value != "" {
				logLevel, err := logrus.ParseLevel(value)
				if err == nil {
					logrus.SetLevel(logLevel)
				} else {
					logrus.Warnf("Unknown log level: %q", value)
				}
			}
		},
	}
	rootCmd.PersistentFlags().String("config", os.Getenv("HOME")+"/.config/iaqualink.json", "Path to the config file")
	rootCmd.PersistentFlags().String("log-level", "info", "Log level {debug,info,warning,error}")

	{
		cmd := &cobra.Command{
			Use:   "login <username> <password>",
			Short: "Login to iAquaLink",
			Long:  ``,
			Args:  cobra.ExactArgs(2),
			Run: func(cmd *cobra.Command, args []string) {
				username := args[0]
				password := args[1]

				client := &iaqualink.Client{}
				output, err := client.Login(username, password)
				if err != nil {
					logrus.Errorf("Error: %v", err)
					os.Exit(1)
				}

				config := Config{
					Username:            username,
					Password:            password,
					AuthenticationToken: output.AuthenticationToken,
					UserID:              output.ID,
				}
				contents, err := json.MarshalIndent(config, "", "   ")
				if err != nil {
					logrus.Errorf("Error: %v", err)
					os.Exit(1)
				}

				configFilename, err := cmd.Flags().GetString("config")
				if err != nil {
					logrus.Errorf("Error: %v", err)
					os.Exit(1)
				}
				ioutil.WriteFile(configFilename, contents, 0644)

				contents, err = json.MarshalIndent(output, "", "   ")
				if err != nil {
					logrus.Errorf("Error: %v", err)
					os.Exit(1)
				}
				fmt.Printf("%s\n", contents)
			},
		}
		rootCmd.AddCommand(cmd)
	}

	{
		cmd := &cobra.Command{
			Use:   "devices",
			Short: "List the iAquaLink devices",
			Long:  ``,
			Args:  cobra.ExactArgs(0),
			Run: func(cmd *cobra.Command, args []string) {
				client, err := buildClient(cmd)
				if err != nil {
					logrus.Errorf("Error: %v", err)
					os.Exit(1)
				}
				output, err := client.ListDevices()
				if err != nil {
					logrus.Errorf("Error: %v", err)
					os.Exit(1)
				}
				contents, err := json.MarshalIndent(output, "", "   ")
				if err != nil {
					logrus.Errorf("Error: %v", err)
					os.Exit(1)
				}
				fmt.Printf("%s\n", contents)
			},
		}
		rootCmd.AddCommand(cmd)
	}

	{
		cmd := &cobra.Command{
			Use:   "device-execute-read-command",
			Short: "Run a command on a device",
			Long:  ``,
			Args:  cobra.MinimumNArgs(1),
			Run: func(cmd *cobra.Command, args []string) {
				deviceID := args[0]
				values := url.Values{}

				for _, parameter := range args[1:] {
					parts := strings.SplitN(parameter, "=", 2)
					key := parts[0]
					value := parts[1]
					values.Set(key, value)
				}

				client, err := buildClient(cmd)
				if err != nil {
					logrus.Errorf("Error: %v", err)
					os.Exit(1)
				}
				output, err := client.DeviceExecuteReadCommand(deviceID, values)
				if err != nil {
					logrus.Errorf("Error: %v", err)
					os.Exit(1)
				}
				contents, err := json.MarshalIndent(output, "", "   ")
				if err != nil {
					logrus.Errorf("Error: %v", err)
					os.Exit(1)
				}
				fmt.Printf("%s\n", contents)
			},
		}
		rootCmd.AddCommand(cmd)
	}

	{
		cmd := &cobra.Command{
			Use:   "device-start",
			Short: "Start the device",
			Long:  ``,
			Args:  cobra.MinimumNArgs(1),
			Run: func(cmd *cobra.Command, args []string) {
				deviceID := args[0]
				values := url.Values{}
				values.Set("request", "0A1240")
				values.Set("timeout", "800")

				client, err := buildClient(cmd)
				if err != nil {
					logrus.Errorf("Error: %v", err)
					os.Exit(1)
				}
				output, err := client.DeviceExecuteReadCommand(deviceID, values)
				if err != nil {
					logrus.Errorf("Error: %v", err)
					os.Exit(1)
				}
				contents, err := json.MarshalIndent(output, "", "   ")
				if err != nil {
					logrus.Errorf("Error: %v", err)
					os.Exit(1)
				}
				fmt.Printf("%s\n", contents)
			},
		}
		rootCmd.AddCommand(cmd)
	}

	{
		cmd := &cobra.Command{
			Use:   "device-stop",
			Short: "Stop the device",
			Long:  ``,
			Args:  cobra.MinimumNArgs(1),
			Run: func(cmd *cobra.Command, args []string) {
				deviceID := args[0]
				values := url.Values{}
				values.Set("request", "0A1210")
				values.Set("timeout", "800")

				client, err := buildClient(cmd)
				if err != nil {
					logrus.Errorf("Error: %v", err)
					os.Exit(1)
				}
				output, err := client.DeviceExecuteReadCommand(deviceID, values)
				if err != nil {
					logrus.Errorf("Error: %v", err)
					os.Exit(1)
				}
				contents, err := json.MarshalIndent(output, "", "   ")
				if err != nil {
					logrus.Errorf("Error: %v", err)
					os.Exit(1)
				}
				fmt.Printf("%s\n", contents)
			},
		}
		rootCmd.AddCommand(cmd)
	}

	{
		cmd := &cobra.Command{
			Use:   "device-status",
			Short: "Show the status of the device",
			Long:  ``,
			Args:  cobra.MinimumNArgs(1),
			Run: func(cmd *cobra.Command, args []string) {
				deviceID := args[0]
				values := url.Values{}
				values.Set("request", "0A11")
				values.Set("timeout", "800")

				client, err := buildClient(cmd)
				if err != nil {
					logrus.Errorf("Error: %v", err)
					os.Exit(1)
				}
				output, err := client.DeviceExecuteReadCommand(deviceID, values)
				if err != nil {
					logrus.Errorf("Error: %v", err)
					os.Exit(1)
				}
				results := map[string]interface{}{}
				results["_response"] = output.Command.Response
				if len(output.Command.Response) == len("001102000BD18FD305E407021F43090F4570") {
					state := output.Command.Response[(2)*2:][:2]
					results["state"] = state
					var stateName string
					switch state {
					case "01":
						stateName = "stopped"
					case "02":
						stateName = "running"
					case "03":
						stateName = "finished"
					case "04":
						stateName = "running"
					case "0A":
						stateName = "lift system"
					case "0B":
						stateName = "remote control"
					case "0D":
						stateName = "error - out of water"
					}
					results["state_name"] = stateName

					cleaningMode := output.Command.Response[(4)*2:][:2]
					results["cleaning_mode"] = cleaningMode
					var cleaningModeName string
					switch cleaningMode {
					case "08":
						cleaningModeName = "floor (standard)"
					case "09":
						cleaningModeName = "floor (high)"
					case "0A":
						cleaningModeName = "floor and walls (standard)"
					case "0B":
						cleaningModeName = "floor and walls (high)"
					case "0C":
						cleaningModeName = "waterline (standard)"
					case "0D":
						cleaningModeName = "waterline (high)"
					}
					results["cleaning_mode_name"] = cleaningModeName

					minutesRemainingString := output.Command.Response[(5)*2:][:2]
					minutesRemaining, err := strconv.ParseInt(minutesRemainingString, 16, 64)
					if err != nil {
						logrus.Warnf("Could not parse minutes remaining: %v", err)
					}
					results["minutes_remaining"] = minutesRemaining

					uptimeString := output.Command.Response[(6)*2:][:4]
					var parts []string
					for len(uptimeString) > 0 {
						part := uptimeString[0:2]
						uptimeString = uptimeString[2:]
						parts = append([]string{part}, parts...)
					}
					uptimeString = strings.Join(parts, "")
					uptime, err := strconv.ParseInt(uptimeString, 16, 64)
					if err != nil {
						logrus.Warnf("Could not parse uptime: %v", err)
					}
					results["uptime"] = uptime
				}
				contents, err := json.MarshalIndent(results, "", "   ")
				if err != nil {
					logrus.Errorf("Error: %v", err)
					os.Exit(1)
				}
				fmt.Printf("%s\n", contents)
			},
		}
		rootCmd.AddCommand(cmd)
	}

	{
		cmd := &cobra.Command{
			Use:   "raw",
			Short: "Perform a raw API command",
			Long:  ``,
			Args:  cobra.MinimumNArgs(2),
			Run: func(cmd *cobra.Command, args []string) {
				method := args[0]
				path := args[1]
				values := url.Values{}

				for _, parameter := range args[2:] {
					parts := strings.SplitN(parameter, "=", 2)
					key := parts[0]
					value := parts[1]
					values.Set(key, value)
				}

				client, err := buildClient(cmd)
				if err != nil {
					logrus.Errorf("Error: %v", err)
					os.Exit(1)
				}
				output, err := client.Raw(method, path, values, nil)
				if err != nil {
					logrus.Errorf("Error: %v", err)
					os.Exit(1)
				}
				fmt.Printf("%s\n", output)
			},
		}
		rootCmd.AddCommand(cmd)
	}

	rootCmd.Execute()
}

func buildClient(cmd *cobra.Command) (*iaqualink.Client, error) {
	configFilename, err := cmd.Flags().GetString("config")
	if err != nil {
		return nil, err
	}
	contents, err := ioutil.ReadFile(configFilename)
	if err != nil {
		return nil, err
	}
	var config Config
	err = json.Unmarshal(contents, &config)
	if err != nil {
		return nil, err
	}
	client := &iaqualink.Client{
		AuthenticationToken: config.AuthenticationToken,
		UserID:              config.UserID,
	}
	return client, nil
}
