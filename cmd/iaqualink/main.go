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
	"github.com/spf13/cobra/doc"
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
			Use:   "generate-docs",
			Short: "Generate the docs for this tool",
			Long:  ``,
			Args:  cobra.ExactArgs(0),
			Run: func(cmd *cobra.Command, args []string) {
				directory, err := cmd.Flags().GetString("directory")
				if err != nil {
					logrus.Errorf("Error: %v", err)
					os.Exit(1)
				}
				if directory == "" {
					logrus.Errorf("Missing output directory; please specify one with \"--directory\".")
					os.Exit(1)
				}
				err = doc.GenMarkdownTree(rootCmd, directory)
				if err != nil {
					logrus.Errorf("Error: %v", err)
					os.Exit(1)
				}
			},
		}
		cmd.Flags().String("directory", "", "The directory to write the docs to")
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
		var deviceID string
		deviceCmd := &cobra.Command{
			Use:   "device",
			Short: "Device commands",
			Long:  ``,
			PersistentPreRun: func(cmd *cobra.Command, args []string) {
				var err error
				deviceID, err = cmd.Flags().GetString("id")
				if err != nil {
					logrus.Errorf("Error: %v", err)
					os.Exit(1)
				}
				if deviceID == "" {
					logrus.Errorf("Missing device ID; please specify one with \"--id\".")
					os.Exit(1)
				}
			},
		}
		deviceCmd.PersistentFlags().String("id", "", "The ID of the device")
		rootCmd.AddCommand(deviceCmd)

		{
			cmd := &cobra.Command{
				Use:   "execute-read-command",
				Short: "Run a command on a device",
				Long:  ``,
				Args:  cobra.MinimumNArgs(0),
				Run: func(cmd *cobra.Command, args []string) {
					values := url.Values{}

					for _, parameter := range args[0:] {
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
			deviceCmd.AddCommand(cmd)
		}

		{
			cmd := &cobra.Command{
				Use:   "start",
				Short: "Start the device",
				Long:  ``,
				Args:  cobra.ExactArgs(0),
				Run: func(cmd *cobra.Command, args []string) {
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
			deviceCmd.AddCommand(cmd)
		}

		{
			cmd := &cobra.Command{
				Use:   "stop",
				Short: "Stop the device",
				Long:  ``,
				Args:  cobra.ExactArgs(0),
				Run: func(cmd *cobra.Command, args []string) {
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
			deviceCmd.AddCommand(cmd)
		}

		{
			cmd := &cobra.Command{
				Use:   "status",
				Short: "Show the status of the device",
				Long:  ``,
				Args:  cobra.ExactArgs(0),
				Run: func(cmd *cobra.Command, args []string) {
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
						input := output.Command.Response

						firstByteString := input[0:2]
						input = input[2:]
						firstByte, err := parseNumberFromLittleEndianHexadecimal(firstByteString)
						if err != nil {
							logrus.Errorf("Error: %v", err)
							os.Exit(1)
						}
						if firstByte != 0x00 {
							logrus.Warnf("Unexpected first byte: %x", firstByte)
						}

						secondByteString := input[0:2]
						input = input[2:]
						secondByte, err := parseNumberFromLittleEndianHexadecimal(secondByteString)
						if err != nil {
							logrus.Errorf("Error: %v", err)
							os.Exit(1)
						}
						if secondByte != 0x11 {
							logrus.Warnf("Unexpected second byte: %x", secondByte)
						}

						stateString := input[0:2]
						input = input[2:]
						state, err := parseNumberFromLittleEndianHexadecimal(stateString)
						if err != nil {
							logrus.Errorf("Error: %v", err)
							os.Exit(1)
						}

						results["state"] = state
						var stateName string
						switch state {
						case 0x01:
							stateName = "stopped"
						case 0x02:
							stateName = "running"
						case 0x03:
							stateName = "finished"
						case 0x04:
							stateName = "running"
						case 0x0A:
							stateName = "lift system"
						case 0x0B:
							stateName = "remote control"
						case 0x0C:
							stateName = "finishing"
						case 0x0D:
							stateName = "error"
						case 0x0E:
							stateName = "error"
						default:
							stateName = "TODO:" + stateString
						}
						results["state_name"] = stateName

						errorStateString := input[0:2]
						input = input[2:]
						errorState, err := parseNumberFromLittleEndianHexadecimal(errorStateString)
						if err != nil {
							logrus.Errorf("Error: %v", err)
							os.Exit(1)
						}

						results["error"] = errorState
						var errorStateName string
						switch errorState {
						case 0x00:
							errorStateName = "none"
						case 0x05:
							errorStateName = "drive motor consumption right"
						case 0x08:
							errorStateName = "out of water"
						case 0x0a:
							errorStateName = "communication"
						default:
							errorStateName = "TODO:" + errorStateString
						}
						results["error_name"] = errorStateName

						cleaningModeString := input[0:2]
						input = input[2:]
						cleaningMode, err := parseNumberFromLittleEndianHexadecimal(cleaningModeString)
						if err != nil {
							logrus.Errorf("Error: %v", err)
							os.Exit(1)
						}

						results["cleaning_mode"] = cleaningMode
						var cleaningModeName string
						switch cleaningMode {
						case 0x08:
							cleaningModeName = "floor (standard)"
						case 0x09:
							cleaningModeName = "floor (high)"
						case 0x0A:
							cleaningModeName = "floor and walls (standard)"
						case 0x0B:
							cleaningModeName = "floor and walls (high)"
						case 0x0C:
							cleaningModeName = "waterline (standard)"
						case 0x0D:
							cleaningModeName = "waterline (high)"
						default:
							cleaningModeName = "TODO:" + cleaningModeString
						}
						results["cleaning_mode_name"] = cleaningModeName

						minutesRemainingString := input[0:2]
						input = input[2:]
						minutesRemaining, err := parseNumberFromLittleEndianHexadecimal(minutesRemainingString)
						if err != nil {
							logrus.Errorf("Error: %v", err)
							os.Exit(1)
						}
						results["minutes_remaining"] = minutesRemaining

						uptimeString := input[0:6]
						input = input[6:]
						uptime, err := parseNumberFromLittleEndianHexadecimal(uptimeString)
						if err != nil {
							logrus.Errorf("Error: %v", err)
							os.Exit(1)
						}
						results["uptime_minutes"] = uptime

						runtimeString := input[0:6]
						input = input[6:]
						runtime, err := parseNumberFromLittleEndianHexadecimal(runtimeString)
						if err != nil {
							logrus.Errorf("Error: %v", err)
							os.Exit(1)
						}
						results["runtime_minutes"] = runtime

						unknown1String := input[0:6]
						input = input[6:]
						unknown1, err := parseNumberFromLittleEndianHexadecimal(unknown1String)
						if err != nil {
							logrus.Errorf("Error: %v", err)
							os.Exit(1)
						}
						results["unknown1"] = unknown1

						unknown2String := input[0:6]
						input = input[6:]
						unknown2, err := parseNumberFromLittleEndianHexadecimal(unknown2String)
						if err != nil {
							logrus.Errorf("Error: %v", err)
							os.Exit(1)
						}
						results["unknown2"] = unknown2

						if len(input) > 0 {
							logrus.Warnf("Extra data in the response: %s", input)
						}
					} else {
						logrus.Warnf("Unexpected response length: %d", len(output.Command.Response))
					}
					contents, err := json.MarshalIndent(results, "", "   ")
					if err != nil {
						logrus.Errorf("Error: %v", err)
						os.Exit(1)
					}
					fmt.Printf("%s\n", contents)
				},
			}
			deviceCmd.AddCommand(cmd)
		}

		{
			cmd := &cobra.Command{
				Use:   "schedule",
				Short: "Show the schedule of the device",
				Long:  ``,
				Args:  cobra.ExactArgs(0),
				Run: func(cmd *cobra.Command, args []string) {
					values := url.Values{}
					values.Set("request", "0A0D")
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
					if len(output.Command.Response) == len("000D7F0300030003000300030003000300") {
						input := output.Command.Response

						firstByteString := input[0:2]
						input = input[2:]
						firstByte, err := parseNumberFromLittleEndianHexadecimal(firstByteString)
						if err != nil {
							logrus.Errorf("Error: %v", err)
							os.Exit(1)
						}
						if firstByte != 0x00 {
							logrus.Warnf("Unexpected first byte: %x", firstByte)
						}

						secondByteString := input[0:2]
						input = input[2:]
						secondByte, err := parseNumberFromLittleEndianHexadecimal(secondByteString)
						if err != nil {
							logrus.Errorf("Error: %v", err)
							os.Exit(1)
						}
						if secondByte != 0x0D {
							logrus.Warnf("Unexpected second byte: %x", secondByte)
						}

						unknown1String := input[0:2]
						input = input[2:]
						unknown1, err := parseNumberFromLittleEndianHexadecimal(unknown1String)
						if err != nil {
							logrus.Errorf("Error: %v", err)
							os.Exit(1)
						}
						results["unknown1"] = unknown1

						days := []string{"monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday"}
						for dayIndex, dayName := range days {
							hourString := input[0:2]
							input = input[2:]
							hour, err := parseNumberFromLittleEndianHexadecimal(hourString)
							if err != nil {
								logrus.Errorf("Error: %v", err)
								os.Exit(1)
							}

							minuteString := input[0:2]
							input = input[2:]
							minute, err := parseNumberFromLittleEndianHexadecimal(minuteString)
							if err != nil {
								logrus.Errorf("Error: %v", err)
								os.Exit(1)
							}

							results[fmt.Sprintf("day_%d_%s", dayIndex, dayName)] = fmt.Sprintf("%02d:%02d", hour, minute)
						}

						if len(input) > 0 {
							logrus.Warnf("Extra data in the response: %s", input)
						}
					} else {
						logrus.Warnf("Unexpected response length: %d", len(output.Command.Response))
					}
					contents, err := json.MarshalIndent(results, "", "   ")
					if err != nil {
						logrus.Errorf("Error: %v", err)
						os.Exit(1)
					}
					fmt.Printf("%s\n", contents)
				},
			}
			deviceCmd.AddCommand(cmd)
		}
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

// buildClient creates an `iaqualink.Client` for the command.
//
// This leverages the "config" flag.
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

// parseNumberFromLittleEndianHexadecimal parses an integer from a little-endian hexadecimal string.
func parseNumberFromLittleEndianHexadecimal(input string) (int64, error) {
	if len(input)%2 != 0 {
		return 0, fmt.Errorf("input length is not a multiple of 2: %d", len(input))
	}

	// Reverse the "bytes" of the input string.
	var parts []string
	for len(input) > 0 {
		part := input[0:2]
		input = input[2:]
		parts = append([]string{part}, parts...)
	}
	input = strings.Join(parts, "")
	// Parse the string as hexadecmial (base 16).
	return strconv.ParseInt(input, 16, 64)
}
