package main

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/jedib0t/go-pretty/v6/table"
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
	IDToken             string `json:"id_token"`
	UserID              string `json:"user_id"`
}

func main() {
	// This is the default config location, including the name of the config ".json" file.
	// This will be whatever the OS thinks the user's config location is, plus an "iaqualink"
	// folder with a "config.json" file in it.
	//
	// If the user ends up using this default value, then we'll also try to create the "iaqualink"
	// folder.  Otherwise, it's the user's problem.
	var defaultConfigLocation string
	{
		userConfigDirectory, err := os.UserConfigDir()
		if err != nil {
			// Oh well; nothing we can do about it.
			userConfigDirectory = ""
		}
		if userConfigDirectory == "" {
			defaultConfigLocation = "config.json"
		} else {
			defaultConfigLocation = filepath.Join(userConfigDirectory, "iaqualink", "config.json")
		}
	}

	rootCmd := &cobra.Command{
		Use:   "iaqualink",
		Short: "iAquaLink client",
		Long: strings.Join(
			[]string{
				`This communicates with an iAquaLink device.`,
				``,
				`The first thing that you'll want to do is the "login" command to log in, using your`,
				`username and password.  This information will be saved in a configuration file so that`,
				`you generally won't have to deal with it again.`,
				``,
				`Once logged in, list your devices using the "devices" command.  Make note of the serial`,
				`number of the device that you'd like to use.`,
				``,
				`Finally, use the "device" subcommand to perform actions on a device.  If you have more`,
				`than one device, you'll need to specify the serial number of the one that you want using`,
				`the --id option.`,
			},
			"\n",
		),
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			// Set the log level based on the value given.
			if value, _ := cmd.Flags().GetString("log-level"); value != "" {
				logLevel, err := logrus.ParseLevel(value)
				if err == nil {
					logrus.SetLevel(logLevel)
				} else {
					logrus.Warnf("Unknown log level: %q", value)
				}
			}

			// If the config location is the default, then create the application folder that the
			// config file will live in.
			if value, _ := cmd.Flags().GetString("config"); value == defaultConfigLocation {
				configDirectory := path.Dir(value)
				// Only attempt to create the parent folder if we actually have one.
				// `path.Dir` will return "." if there is none (and we'll also play it safe and check
				// for the empty string, as well).
				if configDirectory != "" && configDirectory != "." {
					_, err := os.Stat(configDirectory)
					if err != nil && os.IsNotExist(err) {
						os.Mkdir(configDirectory, 0755)
					}
				}
			}
		},
	}
	rootCmd.PersistentFlags().String("config", defaultConfigLocation, "Path to the config file")
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

				// Write the config so that we can use it on subsequent calls.
				{
					config := Config{
						Username:            username,
						Password:            password,
						AuthenticationToken: output.AuthenticationToken,
						IDToken:             output.UserPoolOAuth.IDToken,
						UserID:              output.ID.String(),
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
					err = os.WriteFile(configFilename, contents, 0644)
					if err != nil {
						logrus.Errorf("Could not write config file: %v", err)
					}
				}

				// Log the response contents.
				contents, err := json.MarshalIndent(output, "", "   ")
				if err != nil {
					logrus.Errorf("Error: %v", err)
					os.Exit(1)
				}
				logrus.Debugf("Contents: %s", contents)

				// Print a success message.
				fmt.Printf("Successfully logged in as %s.\n", username)
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
			Short: "List the devices on your account",
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
				logrus.Debugf("Output: %s", contents)

				t := table.NewWriter()
				t.SetOutputMirror(os.Stdout)
				t.AppendHeader(table.Row{"Serial Number", "Name", "Type"})
				for _, device := range output {
					t.AppendRow(table.Row{device.SerialNumber, device.Name, device.DeviceType})
				}
				t.Render()
			},
		}
		rootCmd.AddCommand(cmd)
	}

	{
		var deviceID string
		var deviceType string
		deviceCmd := &cobra.Command{
			Use:   "device",
			Short: "Perform device-specific actions",
			Long:  ``,
			PersistentPreRun: func(cmd *cobra.Command, args []string) {
				rootCmd.PersistentPreRun(cmd, args)

				var err error
				deviceID, err = cmd.Flags().GetString("id")
				if err != nil {
					logrus.Errorf("Error: %v", err)
					os.Exit(1)
				}
				// If no device was specified, see if there's only one possibility.
				// If so, use that.  Otherwise, fail with an error.
				if deviceID == "" {
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
					if len(output) == 1 {
						for _, device := range output {
							logrus.Debugf("Found device %s", device.SerialNumber)
							deviceID = device.SerialNumber
							break
						}
					}

					if deviceID == "" {
						logrus.Errorf("Missing device ID; please specify one with \"--id\".")
						os.Exit(1)
					}
				}

				deviceType, err = cmd.Flags().GetString("type")
				if err != nil {
					logrus.Errorf("Error: %v", err)
					os.Exit(1)
				}

				if deviceType == "" {
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
					for _, device := range output {
						logrus.Debugf("Found device %s (looking for %s)", device.SerialNumber, deviceID)
						if device.SerialNumber == deviceID {
							deviceType = device.DeviceType
							break
						}
					}
				}
				logrus.Debugf("Device type: %s", deviceType)
			},
		}
		deviceCmd.PersistentFlags().String("id", "", "The ID of the device (use the serial number)")
		deviceCmd.PersistentFlags().String("type", "", "Override the type of the device")
		rootCmd.AddCommand(deviceCmd)

		{
			cmd := &cobra.Command{
				Use:   "execute-read-command",
				Short: "Run a command on a device",
				Long:  ``,
				Args:  cobra.MinimumNArgs(0),
				Run: func(cmd *cobra.Command, args []string) {
					if deviceType != iaqualink.DeviceTypeI2DRobot {
						logrus.Errorf("Expected device type: %s", iaqualink.DeviceTypeI2DRobot)
						os.Exit(1)
					}

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
				Use:   "features",
				Short: "List the features of a device",
				Long:  ``,
				Args:  cobra.ExactArgs(0),
				Run: func(cmd *cobra.Command, args []string) {
					if deviceType != iaqualink.DeviceTypeCycloneXT {
						logrus.Errorf("Expected device type: %s", iaqualink.DeviceTypeCycloneXT)
						os.Exit(1)
					}

					client, err := buildClient(cmd)
					if err != nil {
						logrus.Errorf("Error: %v", err)
						os.Exit(1)
					}
					output, err := client.DeviceFeatures(deviceID)
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
				Use:   "ota",
				Short: "Show the OTA information",
				Long:  ``,
				Args:  cobra.ExactArgs(0),
				Run: func(cmd *cobra.Command, args []string) {
					if deviceType != iaqualink.DeviceTypeCycloneXT {
						logrus.Errorf("Expected device type: %s", iaqualink.DeviceTypeCycloneXT)
						os.Exit(1)
					}

					client, err := buildClient(cmd)
					if err != nil {
						logrus.Errorf("Error: %v", err)
						os.Exit(1)
					}
					output, err := client.DeviceOTA(deviceID)
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
				Use:   "site",
				Short: "Show the site information",
				Long:  ``,
				Args:  cobra.ExactArgs(0),
				Run: func(cmd *cobra.Command, args []string) {
					if deviceType != iaqualink.DeviceTypeCycloneXT {
						logrus.Errorf("Expected device type: %s", iaqualink.DeviceTypeCycloneXT)
						os.Exit(1)
					}

					client, err := buildClient(cmd)
					if err != nil {
						logrus.Errorf("Error: %v", err)
						os.Exit(1)
					}
					output, err := client.DeviceSite(deviceID)
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
					client, err := buildClient(cmd)
					if err != nil {
						logrus.Errorf("Error: %v", err)
						os.Exit(1)
					}

					switch deviceType {
					case iaqualink.DeviceTypeI2DRobot:
						values := url.Values{}
						values.Set("request", "0A1240")
						values.Set("timeout", "800")

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
					case iaqualink.DeviceTypeCycloneXT:
						output, err := client.DeviceWebSocket(deviceID, "start")
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
					}
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
					client, err := buildClient(cmd)
					if err != nil {
						logrus.Errorf("Error: %v", err)
						os.Exit(1)
					}

					switch deviceType {
					case iaqualink.DeviceTypeI2DRobot:
						values := url.Values{}
						values.Set("request", "0A1210")
						values.Set("timeout", "800")

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
					case iaqualink.DeviceTypeCycloneXT:
						output, err := client.DeviceWebSocket(deviceID, "stop")
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
					}
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
					client, err := buildClient(cmd)
					if err != nil {
						logrus.Errorf("Error: %v", err)
						os.Exit(1)
					}

					switch deviceType {
					case iaqualink.DeviceTypeI2DRobot:
						values := url.Values{}
						values.Set("request", "0A11")
						values.Set("timeout", "800")

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
							case 0x04:
								errorStateName = "pump motor consumption"
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
							switch cleaningMode & 0x0f {
							case 0x8:
								cleaningModeName = "floor (standard)"
							case 0x9:
								cleaningModeName = "floor (high)"
							case 0xA:
								cleaningModeName = "floor and walls (standard)"
							case 0xB:
								cleaningModeName = "floor and walls (high)"
							case 0xC:
								cleaningModeName = "waterline (standard)"
							case 0xD:
								cleaningModeName = "waterline (high)"
							default:
								cleaningModeName = "TODO:" + fmt.Sprintf("0x%x", cleaningMode&0x0f)
							}
							results["cleaning_mode_name"] = cleaningModeName

							var canisterStateName string
							switch (cleaningMode & 0xf0) >> 4 {
							case 0x0:
								canisterStateName = "okay"
							case 0x1:
								canisterStateName = "full"
							default:
								canisterStateName = "TODO:" + fmt.Sprintf("0x%x", (cleaningMode&0xf0)>>4)
							}
							results["canister_state"] = canisterStateName

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
					case iaqualink.DeviceTypeCycloneXT:
						output, err := client.DeviceWebSocket(deviceID)
						if err != nil {
							logrus.Errorf("Error: %v", err)
							os.Exit(1)
						}

						results := map[string]interface{}{}
						if value := output["mode"]; value != "" {
							results["mode"] = value
							switch fmt.Sprintf("%v", value) {
							case "0":
								results["mode_name"] = "stopped"
							case "1":
								results["mode_name"] = "running"
							}
						}

						contents, err := json.MarshalIndent(results, "", "   ")
						if err != nil {
							logrus.Errorf("Error: %v", err)
							os.Exit(1)
						}
						fmt.Printf("%s\n", contents)
					}
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
					if deviceType != iaqualink.DeviceTypeI2DRobot {
						logrus.Errorf("Expected device type: %s", iaqualink.DeviceTypeI2DRobot)
						os.Exit(1)
					}

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
				output, err := client.Raw(method, "" /*TODO:base*/, path, values, nil)
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
	contents, err := os.ReadFile(configFilename)
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
		IDToken:             config.IDToken,
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
