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

// APIKey is the API key to use when talking to the APIs.
// This appears to be a constant.
const APIKey = "EOOEMOW4YR6QNB07"
const IAquaLinkAPIBase = "https://r-api.iaqualink.net"
const WebSocketAPIBase = "https://prod-socket.zodiac-io.com"
const ZodiacAPIBase = "https://prod.zodiac-io.com"

// DeviceType constants.
const (
	DeviceTypeCycloneXT = "cyclonext"
	DeviceTypeI2DRobot  = "i2d_robot"
)

// Feature constants.
const (
	FeatureModeInfo        = "mode_info"
	FeaturepresetDeepUltra = "preset_deep_ultra"
	FeatureQuickClean      = "quick_clean"
	FeatureStartStop       = "start_stop"
	FeatureStatus          = "status"
	FeatureTimer           = "timer"
)

// Client is the iAquaLink client.
type Client struct {
	IAquaLinkAPIBase string // The iAquaLink API base.  If empty, this will default to `IAquaLinkAPIBase`.
	WebSocketAPIBase string // The Web Socket API base.  If empty, this will default to `WebSocketAPIBase`.
	ZodiacAPIBase    string // The Zodiac API base.  If empty, this will default to `ZodiacAPIBase`.

	APIKey string // The API key.  If empty, this will default to `APIKey`.

	AuthenticationToken string // The API token.
	IDToken             string // The OAuth ID token.
	UserID              string // The user ID.

	Client *http.Client // The HTTP client.
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
	Country     string `json:"country"`
	CreatedAt   string `json:"created_at"` // Should be `time.Time`, but oh well.
	Credentials struct {
		AccessKeyID  string `json:"AccessKeyId"`
		Expiration   string `json:"Expiration"` // Should be `time.Time`, but oh well.
		IdentityID   string `json:"IdentityId"`
		SecretKey    string `json:"SecretKey"`
		SessionToken string `json:"SessionToken"`
	} `json:"credentials"`
	Email         string `json:"email"`
	FirstName     string `json:"first_name"`
	ID            string `json:"id"`
	LastName      string `json:"last_name"`
	OptIn1        string `json:"opt_in_1"`
	OptIn2        string `json:"opt_in_2"`
	Phone         string `json:"phone"`
	PostalCode    string `json:"postal_code"`
	Role          string `json:"role"`
	SessionID     string `json:"session_id"`
	State         string `json:"state"`
	TimeZone      string `json:"time_zone"`
	UpdatedAt     string `json:"updated_at"` // Should be `time.Time`, but oh well.
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

// DeviceExecuteReadCommandOutput is the output of executing a command.
type DeviceExecuteReadCommandOutput struct {
	Command struct {
		Request  string `json:"request"`
		Response string `json:"response"`
	} `json:"command"`
	RequestID string `json:"requestID"`
}

// DeviceFeaturesOutput is the output of listing the features.
type DeviceFeaturesOutput struct {
	DeviceID string   `json:"deviceId"`
	Features []string `json:"features"`
	ID       string   `json:"id"`
	Model    string   `json:"model"`
}

// DeviceOTAOutput is the output of querying for an OTA update.
type DeviceOTAOutput struct {
	DeviceID string `json:"deviceId"`
	Status   string `json:"status"`
}

// DeviceSiteOutput is the output of listing the features.
type DeviceSiteOutput struct {
	DaylightSavings int    `json:"daylight_savings"` // 1 if daylight saving time; 0 otherwise.
	TimeZone        string `json:"time_zone"`        // In the format of "[+-][0-9][0-9]:[0-9][0-9]".
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
	if c.WebSocketAPIBase == "" {
		c.WebSocketAPIBase = WebSocketAPIBase
	}
	if c.ZodiacAPIBase == "" {
		c.ZodiacAPIBase = ZodiacAPIBase
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
	request, err := http.NewRequest(http.MethodPost, c.ZodiacAPIBase+"/users/v1/login", bytes.NewReader(contents))
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
		c.IDToken = output.UserPoolOAuth.IDToken
		return &output, nil
	}
	return nil, fmt.Errorf("received bad status code: %d", response.StatusCode)
}

// Raw performs a raw request using the API.
func (c *Client) Raw(method string, base string, path string, parameters url.Values, input interface{}) ([]byte, error) {
	c.init()

	if base == "" {
		base = c.IAquaLinkAPIBase
	}
	urlString := base + "/" + strings.TrimLeft(path, "/")
	urlParameters := url.Values{}
	if base == c.IAquaLinkAPIBase {
		urlParameters.Set("api_key", c.APIKey)                           // TODO: Should we explicitly add this?
		urlParameters.Set("authentication_token", c.AuthenticationToken) // TODO: Should we explicitly add this?
		urlParameters.Set("user_id", c.UserID)                           // TODO: Should we explicitly add this?
	}
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
	if base == c.ZodiacAPIBase {
		request.Header.Set("Authorization", c.IDToken) // TODO: Should we explicitly add this?
		request.Header.Set("User-Agent", "iAqualink/578 CFNetwork/1335.0.3 Darwin/21.6.0")
	}
	logrus.Debugf("Headers: %v", request.Header)

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
	c.init()

	contents, err := c.Raw(http.MethodGet, c.IAquaLinkAPIBase, "/devices.json", nil, nil)
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
	c.init()

	values := url.Values{}
	values.Set("command", "/command")
	values.Set("params", inputValues.Encode())

	contents, err := c.Raw(http.MethodPost, c.IAquaLinkAPIBase, "/devices/"+url.PathEscape(deviceID)+"/execute_read_command.json", values, nil)
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

// DeviceFeatures lists the device features.
func (c *Client) DeviceFeatures(deviceID string) (*DeviceFeaturesOutput, error) {
	c.init()

	values := url.Values{}

	contents, err := c.Raw(http.MethodGet, c.ZodiacAPIBase, "/devices/v2/"+url.PathEscape(deviceID)+"/features", values, nil)
	if err != nil {
		return nil, err
	}
	var output DeviceFeaturesOutput
	err = json.Unmarshal(contents, &output)
	if err != nil {
		return nil, err
	}
	return &output, nil
}

// DeviceOTA lists the device features.
func (c *Client) DeviceOTA(deviceID string) (*DeviceOTAOutput, error) {
	c.init()

	values := url.Values{}

	contents, err := c.Raw(http.MethodGet, c.ZodiacAPIBase, "/devices/v2/"+url.PathEscape(deviceID)+"/ota", values, nil)
	if err != nil {
		return nil, err
	}
	var output DeviceOTAOutput
	err = json.Unmarshal(contents, &output)
	if err != nil {
		return nil, err
	}
	return &output, nil
}

// DeviceSite lists the device features.
func (c *Client) DeviceSite(deviceID string) (*DeviceSiteOutput, error) {
	c.init()

	values := url.Values{}

	contents, err := c.Raw(http.MethodGet, c.ZodiacAPIBase, "/devices/v2/"+url.PathEscape(deviceID)+"/site", values, nil)
	if err != nil {
		return nil, err
	}
	var output DeviceSiteOutput
	err = json.Unmarshal(contents, &output)
	if err != nil {
		return nil, err
	}
	return &output, nil
}
