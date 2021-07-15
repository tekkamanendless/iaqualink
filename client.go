package iaqualink

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
)

const APIKey = "EOOEMOW4YR6QNB07"
const IAquaLinkAPIBase = "https://r-api.iaqualink.net"
const LoginAPIBase = "https://prod.zodiac-io.com"

// Client is the iAquaLink client.
type Client struct {
	APIKey              string       // The API key.  If empty, this will default to `APIKey`.
	LoginAPIBase        string       // The login API base.  If empty, this will default to `LoginAPIBase`.
	IAquaLinkAPIBase    string       // The iAquaLink API base.  If empty, this will default to `IAquaLinkAPIBase`.
	AuthenticationToken string       // The API token.
	Client              *http.Client // The HTTP client.
	UserID              string       // The user ID.
}

// LoginInput is the login input.
type LoginInput struct {
	APIKey   string `json:"apiKey"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

// LoginOutput is the login output.
type LoginOutput struct {
	Address             string `json:"address"`
	Address1            string `json:"address_1"`
	Address2            string `json:"address_2"`
	AuthenticationToken string `json:"authentication_token"`
	City                string `json:"city"`
	CognitoPool         struct {
		AppClientID string `json:"appClientId"`
		PoolID      string `json:"poolId"`
		Region      string `json:"region"`
	} `json:"cognitoPool"`
	Country     string    `json:"country"`
	CreatedAt   time.Time `json:"created_at"`
	Credentials struct {
		AccessKeyID  string    `json:"AccessKeyId"`
		Expiration   time.Time `json:"Expiration"`
		IdentityID   string    `json:"IdentityId"`
		SecretKey    string    `json:"SecretKey"`
		SessionToken string    `json:"SessionToken"`
	} `json:"credentials"`
	Email         string    `json:"email"`
	FirstName     string    `json:"first_name"`
	ID            string    `json:"id"`
	LastName      string    `json:"last_name"`
	OptIn1        string    `json:"opt_in_1"`
	OptIn2        string    `json:"opt_in_2"`
	Phone         string    `json:"phone"`
	PostalCode    string    `json:"postal_code"`
	Role          string    `json:"role"`
	SessionID     string    `json:"session_id"`
	State         string    `json:"state"`
	TimeZone      string    `json:"time_zone"`
	UpdatedAt     time.Time `json:"updated_at"`
	UserPoolOAuth struct {
		AccessToken  string `json:"AccessToken"`
		ExpiresIn    int    `json:"ExpiresIn"`
		IDToken      string `json:"IdToken"`
		RefreshToken string `json:"RefreshToken"`
		TokenType    string `json:"TokenType"`
	} `json:"userPoolOAuth"`
	Username string `json:"username"`
}

// ListDevicesOutput is the output of listing the devices.
type ListDevicesOutput []struct {
	ID                    int        `json:"id"`
	SerialNumber          string     `json:"serial_number"`
	CreatedAt             time.Time  `json:"created_at"`
	UpdatedDat            time.Time  `json:"updated_at"`
	Name                  string     `json:"name"`
	DeviceType            string     `json:"device_type"`
	OwnerID               int        `json:"owner_id"`
	Updating              bool       `json:"updating"`
	FirmwareVersion       *string    `json:"firmware_version"`
	TargetFirmwareVersion *string    `json:"target_firmware_version"`
	UpdateFirmwareStartAt *time.Time `json:"update_firmware_start_at"`
	LastActivityAt        *time.Time `json:"last_activity_at"`
}

// DeviceExecuteReadCommand is the output of executing a command.
type DeviceExecuteReadCommandOutput struct {
	Command struct {
		Request  string `json:"request"`
		Response string `json:"response"`
	} `json:"command"`
	RequestID string `json:"requestID"`
}

// init initializes the client.
// This sets all of the default values.
func (c *Client) init() {
	if c.APIKey == "" {
		c.APIKey = APIKey
	}
	if c.IAquaLinkAPIBase == "" {
		c.IAquaLinkAPIBase = IAquaLinkAPIBase
	}
	if c.LoginAPIBase == "" {
		c.LoginAPIBase = LoginAPIBase
	}
	if c.Client == nil {
		c.Client = &http.Client{}
	}
}

// Login with the given username and password.
func (c *Client) Login(username, password string) (*LoginOutput, error) {
	c.init()

	input := LoginInput{
		APIKey:   c.APIKey,
		Email:    username,
		Password: password,
	}
	contents, err := json.Marshal(input)
	if err != nil {
		return nil, err
	}
	request, err := http.NewRequest(http.MethodPost, c.LoginAPIBase+"/users/v1/login", bytes.NewReader(contents))
	if err != nil {
		return nil, err
	}
	response, err := c.Client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	contents, err = io.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}
	if response.StatusCode >= 200 && response.StatusCode <= 299 {
		var output LoginOutput
		err = json.Unmarshal(contents, &output)
		if err != nil {
			return nil, err
		}
		c.AuthenticationToken = output.AuthenticationToken
		c.UserID = output.ID
		return &output, nil
	}
	return nil, fmt.Errorf("received bad status code: %d", response.StatusCode)
}

// Raw performs a raw request using the API.
func (c *Client) Raw(method string, path string, parameters url.Values, input interface{}) ([]byte, error) {
	c.init()

	urlString := c.IAquaLinkAPIBase + "/" + strings.TrimLeft(path, "/")
	urlParameters := url.Values{}
	urlParameters.Set("api_key", c.APIKey)
	urlParameters.Set("authentication_token", c.AuthenticationToken)
	urlParameters.Set("user_id", c.UserID)
	for key, values := range parameters {
		if len(values) > 0 {
			urlParameters.Set(key, values[0])
		}
	}
	if len(urlParameters) > 0 {
		urlString += "?" + urlParameters.Encode()
	}

	logrus.Debugf("%s %s", method, urlString)

	var inputReader io.Reader
	if input != nil {
		contents, err := json.Marshal(input)
		if err != nil {
			return nil, err
		}
		inputReader = bytes.NewReader(contents)
	}
	request, err := http.NewRequest(method, urlString, inputReader)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Accept", "application/json")

	response, err := c.Client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	contents, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}
	if response.StatusCode >= 200 && response.StatusCode <= 299 {
		return contents, nil
	}
	logrus.Warnf("[contents] %s", contents)
	return nil, fmt.Errorf("received bad status code: %d", response.StatusCode)
}

// ListDevices lists the devices.
func (c *Client) ListDevices() (ListDevicesOutput, error) {
	contents, err := c.Raw(http.MethodGet, "/devices.json", nil, nil)
	if err != nil {
		return nil, err
	}
	var output ListDevicesOutput
	err = json.Unmarshal(contents, &output)
	if err != nil {
		return nil, err
	}
	return output, nil
}

// DeviceExecuteReadCommand executes a command.
func (c *Client) DeviceExecuteReadCommand(deviceID string, inputValues url.Values) (*DeviceExecuteReadCommandOutput, error) {
	values := url.Values{}
	values.Set("command", "/command")
	values.Set("params", inputValues.Encode())

	contents, err := c.Raw(http.MethodPost, "/devices/"+url.PathEscape(deviceID)+"/execute_read_command.json", values, nil)
	if err != nil {
		return nil, err
	}
	var output DeviceExecuteReadCommandOutput
	err = json.Unmarshal(contents, &output)
	if err != nil {
		return nil, err
	}
	return &output, nil
}
