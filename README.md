[![Go Report Card](https://goreportcard.com/badge/github.com/tekkamanendless/iaqualink)](https://goreportcard.com/report/github.com/tekkamanendless/iaqualink)
[![GoDoc](https://godoc.org/github.com/tekkamanendless/iaqualink?status.svg)](https://godoc.org/github.com/tekkamanendless/iaqualink)

# iaqualink
Go package for talking with iAquaLink/Zodiac pool robots.

This package has been built by reverse-engineering the iAquaLink HTTP protocol using `mitmproxy`.

This package is very much in development, and there's a good chance that your specific pool robot is not properly supported.
If you'd like to help out, set up an `mitmproxy` and send me your traffic.

## Tested With

* Polaris P965IQ (device type `i2d_robot`)
* Zodiac Voyager RE 4400 iQ (device type `cyclonext`)

## Device Types

* `cyclonext`; this definitely includes teh Zodiac Voyager.
* `exo`; this appears to be a chlorinator of some kind.
* `id2_robot`; this definitely includes the Polaris IQ models.

## Zodiac API
Base: https://prod.zodiac-io.com

### `POST /devices/v1/${device}/ota`
Returns information on if the device has an update available.

Headers:

* `Authorization`: the ID token.

JSON request:

* `deviceType`; the device type.
* `forceOTA`; either `true` or `false` (I've only ever seen it use `true`).

JSON response:

* `code`; some kind of numeric code.
* `message`; a human-readable message.

The only values that I'm aware of so far are:

* `6`: `Device is already on latest firmware`

### `GET /devices/v2/${device}/shadow`
This seems to be identical to `GET /devices/v1/${device}/shadow`.

### `POST /devices/v1/${device}/shadow`
This appears to let you update the state of the device.

Headers:

* `Authorization`: the ID token.

JSON request:

* `state`
    * `desired`
        * `equipment`
            * `${key}`; this is the key returned by the `GET` version of the endpoint.
                * (Whatever field(s?) you want to change.

For example, for an `exo` chlorinator, you might set `production: 1` or `production: 0` to turn it on or off, respectively.

JSON response:

This is practically identical to the response from `GET /devices/v2/${device}/shadow`.

### `GET /devices/v2/${device}/features`
This returns a list of features that the device supports.

Headers:

* `Authorization`: the ID token.

### `GET /devices/v2/${device}/info`
TODO: ???

Headers:

* `Authorization`: the ID token.

### `GET /devices/v2/${device}/site`
TODO: ???

Headers:

* `Authorization`: the ID token.

### `GET /devices/v2/${device}/shadow`
This appears to return the current state of the device.

Headers:

* `Authorization`: the ID token.

JSON response:

* `deviceId`; the device identifier.
* `state`; the state.
    * `reported`; the state information as reported by the device.
        * `aws`; probably AWS-related debug information?
        * `debug`; debug information?
        * `equipment`; an object where each key represents a thing of some kind that can be manipulated.
            * `${key}`; a thing of some kind.  The properties vary based on the device type.
        * (There are other fields)

### `POST /push/v1/users/unregister-mobile`
TODO: ???

### `POST /users/v1/login`
This logs you into the Zodiac API and provides you with a user ID and authentication token.
These will be used by the iAquaLink API.

JSON body:

* `apiKey`: `EOOEMOW4YR6QNB07`; this appears to be constant.
* `email`; your e-mail address.
* `password`; your password.

JSON response (relevant subset):

* `authentication_token`; this is the authentication token.
* `email`; the same e-mail address.
* `id`; this is the user ID.
* `session_id`; ???
* `userPoolOAuth`; this contains information about OAuth, which is used for newer robot models.
    * `AccessToken`; the access token.
    * `ExpiresIn`; when the (access?) token expires.
    * `IdToken`; the ID token.
    * `RefreshToken`; the refresh token; this can be used to get a new `AccessToken` value.
    * `TokenType`; this seems to always be `Bearer`, even though it's not technically used correctly.

### `POST /users/v1/refresh`
This uses the user's e-mail addresss and `RefreshToken` to effectively log in again.

JSON body:

* `email`; the user's e-mail address.
* `refresh_token`; the user's `refreshToken` from `POST /users/v1/login`.

JSON response:

The output is similar to that of `POST /users/v1/login`.
Note, however, that `userPoolOAuth.RefreshToken` will not be present.

## iAquaLink PRM(?) API
Base: https://prm.iaqualink.net

### `POST /v2/signout`
TODO: ???

Headers:

* `Authorization`: the authorization token.

## iAquaLink API
Base: https://r-api.iaqualink.net

### `GET /devices.json`
This lists the devices on your account.
You'll need the device ID for any device-related endpoints.

Query parameters:

* `api_key`: `EOOEMOW4YR6QNB07`; this appears to be constant
* `authentication_token`; your authentication token
* `user_id`; your user ID

Response JSON:

* An array of objects, each representing a device.
    * `device_type`; the device type.
    * `name`; the name given by the user.
    * `serial_number`; the identifier that will be used to subsequently identify the device.

(There are other fields, but they aren't particularly helpful.)

### `POST /devices/${device}/execute_read_command.json`
This executes a command on a device.

Query parameters:

* `api_key`: `EOOEMOW4YR6QNB07`; this appears to be constant
* `authentication_token`; your authentication token
* `user_id`; your user ID
* `command`; the command
* `params`; a query string for the parameters for the command

Commands:

* `/command`
    * Parameters:
        * `request`; the request code
		* `timeout`; the timeout (iAquaLink default: `800`)

Request codes:

* `OAOD`; list the schedule
* `OA11`; list the status
* `0A1210`; stop / clear error
* `0A1240`; start
* `0A1300`; subtract 30 minutes
* `0A1301`; add 30 minutes
* `0A1700`; lift system, stop
* `0A1701`; lift system, lift
* `0A1B42`; backward
* `0A1B46`; forward
* `0A1B4C`; turn left
* `0A1B52`; turn right

Request code format:

* `0A` `<command>` [`<subcommand>`]

Commands:

* `0D`; list the schedule
* `11`; list the status
* `12`; start/stop
    * `10`; stop / clear error
    * `40`; start

* `13`; add/subtract time
    * `00`; subtract 30 minutes
    * `01`; add 30 minutes

* `17`; lift system
    * `00`; stop
    * `01`; start

* `1B`; remote control
    * `42`; ASCII "B" - backward
    * `46`; ASCII "F" - forward
    * `4C`; ASCII "L" - left
    * `52`; ASCII "R" - right

## Web Socket API
Base: https://prod-socket.zodiac-io.com

### `/devices`
This endpoint appears to be the main endpoint for communication (when supported).

Note that in responses, the `metadata` object appears to be a mirror of `state`, but with timestamps where every bottom-level property is.

#### Action: Subscribe
SEND:

```
{
    "action": "subscribe",
    "version": 1,
    "namespace": "authorization",
    "payload": {
        "userId": ${userId}
    },
    "service": "Authorization",
    "target": "${device}"
}
```

RECEIVE:

```
{
    "service": "Authorization",
    "target": "${device}",
    "namespace": "authorization",
    "payload": {
        "robot": {
            "state": {
                "reported": {
                    "aws": {
                        "status": "connected",
                        "timestamp": 1663228298244,
                        "session_id": "11ae4f85-2f9b-4b82-b726-3528c876ea0e"
                    },
                    "sn": "${device}",
                    "dt": "cyc",
                    "vr": "V21C10",
                    "payloadVer": 1,
                    "eboxData": {
                        "controlBoxSn": "${some-serial-number}",
                        "controlBoxPn": "${some-part-number}",
                        "completeCleanerSn": "${some-serial-number}",
                        "completeCleanerPn": "${some-part-number}",
                        "powerSupplySn": "${some-serial-number}",
                        "motorBlockSn": "${some-serial-number}"
                    },
                    "equipment": {
                        "robot.1": {
                            "mode": 0,
                            "direction": 0,
                            "cycle": 3,
                            "cycleStartTime": 1663140417,
                            "canister": 0,
                            "logger": 0,
                            "firstSmrtFlag": 1,
                            "stepper": 0,
                            "stepperAdjTime": 15,
                            "durations": {
                                "waterTim": 45,
                                "quickTim": 90,
                                "smartTim": 0,
                                "deepTim": 150,
                                "customTim": 75,
                                "firstSmartTim": 150,
                                "scanTim": 30
                            },
                            "customCyc": {
                                "type": 0,
                                "intensity": 0
                            },
                            "errors": {
                                "timestamp": 1663097347,
                                "code":0
                            },
                            "vr": "V21E11",
                            "equipmentId": "ND21015155",
                            "totRunTime": 13410
                        }
                    }
                }
            },
            "metadata": {
                "reported": {
                    "aws": {
                        "status": { "timestamp": 1663228298 },
                        "timestamp": { "timestamp": 1663228298 },
                        "session_id": { "timestamp": 1663228298 }
                    },
                    "sn": { "timestamp": 1662828488 },
                    "dt": { "timestamp": 1662828488 },
                    "vr": { "timestamp": 1662828488 },
                    "payloadVer": { "timestamp": 1662828488 },
                    "eboxData": {
                        "controlBoxSn": { "timestamp": 1662828488 },
                        "controlBoxPn": { "timestamp": 1662828488 },
                        "completeCleanerSn": { "timestamp": 1662828488 },
                        "completeCleanerPn": { "timestamp": 1662828488 },
                        "powerSupplySn": { "timestamp": 1662828488 },
                        "motorBlockSn": { "timestamp":1662828488 }
                    },
                    "equipment": {
                        "robot.1": {
                            "mode": { "timestamp": 1663228321 },
                            "direction": { "timestamp": 1662828488 },
                            "cycle": { "timestamp": 1663228321 },
                            "cycleStartTime": { "timestamp": 1663140419 },
                            "canister": { "timestamp": 1662828488 },
                            "logger": { "timestamp": 1662828488 },
                            "firstSmrtFlag": { "timestamp": 1662828488 },
                            "stepper": { "timestamp": 1662828488 },
                            "stepperAdjTime": { "timestamp":1662828488 },
                            "durations": {
                                "waterTim": { "timestamp": 1662828488 },
                                "quickTim": { "timestamp": 1662828488 },
                                "smartTim": { "timestamp": 1662828488 },
                                "deepTim": { "timestamp": 1662828488 },
                                "customTim": { "timestamp": 1662828488 },
                                "firstSmartTim": { "timestamp": 1662828488 },
                                "scanTim": { "timestamp": 1662828488 }
                            },
                            "customCyc": {
                                "type": { "timestamp": 1662828488 },
                                "intensity": { "timestamp": 1662828488 }
                            },
                            "errors": {
                                "timestamp": { "timestamp": 1663140402 },
                                "code": { "timestamp": 1663140402 }
                            },
                            "vr": { "timestamp": 1662828489 },
                            "equipmentId": { "timestamp": 1662828489 },
                            "totRunTime": { "timestamp": 1663149719 }
                        }
                    }
                }
            },
            "version": 230169,
            "timestamp": 1663228422
        },
        "data": [],
        "ota": {
            "status": "UP_TO_DATE"
        }
    }
}
```

#### Action: Start cleaning
As far as I can tell, the `clientToken` appears to be a random identifier for matching the request with a subsequent event.

SEND:

```
{
    "action": "setState",
    "version": 1,
    "namespace": "cyclonext",
    "payload": {
        "state": {
            "desired": {
                "equipment": {
                    "robot.1": {
                        "mode": 1
                    }
                }
            }
        },
        "clientToken": "${userId}|AuWGRMyOKDfMvkU4vhK5wj|l8KVqVChow1lV69CcBad0b"
    },
    "service": "StateController",
    "target": "${device}"
}
```

RECEIVE:
```
{
    "service": "StateStreamer",
    "target": "${device}",
    "event": "StateReported",
    "version": 1,
    "payload": {
        "state": {
            "desired": {
                "equipment": {
                    "robot.1": {
                        "mode": 1
                    }
                }
            }
        },
        "metadata": {
            "desired": {
                "equipment": {
                    "robot.1": {
                        "mode": { "timestamp": 1663228439 }
                    }
                }
            }
        },
        "version": 230170,
        "timestamp": 1663228439,
        "clientToken": "${userId}|AuWGRMyOKDfMvkU4vhK5wj|l8KVqVChow1lV69CcBad0b"
    }
}
```

#### Action: Stop Cleaning
As far as I can tell, the `clientToken` appears to be a random identifier for matching the request with a subsequent event.

SEND:

```
{
    "action": "setState",
    "version": 1,
    "namespace": "cyclonext",
    "payload": {
        "state": {
            "desired": {
                "equipment": {
                    "robot.1": {
                        "mode": 0
                    }
                }
            }
        },
        "clientToken": "${userId}|AuWGRMyOKDfMvkU4vhK5wj|CUXkLn7Dyb0OIplLCBVtAQ"
    },
    "service": "StateController",
    "target": "KK2100006435"
}
```

## Other Secret(?) Web Socket API
Base: https://a1zi08qpbrtjyq-ats.iot.us-east-1.amazonaws.com

### `/mqtt`
This endpoint appears to be the main endpoint for communication (when supported).

Query parameters:

* `X-Amz-Algorithm`: `AWS4-HMAC-SHA256`; (?)
* `X-Amz-Credential`; this appears to be the value from `/login`'s `credentials.AccessKeyId`, followed by `/`, then the date as `YYYYMMDD`, then the region (from `credentials.IdentityId`?), followed by `/`, then `iotdata`, followed by `/`, and then `aws4_request`.
* `X-Amz-Date`; this is a date of some kind of the format `YYYYMMDDTHHMMSSZ`.
* `X-Amz-SignedHeaders`: `host`; (?)
* `X-Amz-Signature`; this looks like a SHA sum of some kind (for example: `ab4a5bc3e82c19584ca1de54d55d1538a4775f4cf`)

I have no idea how to find or create those parameters.

The web socket communication also appears to be in binary format, and I haven't figured out how to decode it yet.

### ???
Perhaps also on this API is:

* `/aws/things/${device}/shadow/get/accepted` (?)

## iAquaLink API Command Responses
The response is plain text representing hexadecimal data (no spaces).

Response code format:

* `00` `<command>` `<specific response>`

### Simple Responses
These commands all seem to respond back with a specific response of `01`, which I'm assuming is a basic acknowledgement.

* Start/clear error response
    ```
    0012 01
    ```

* Add/subtract time response
    ```
    0013 01
    ```

* Lift system, lift/stop response
    ```
    0017 01
    ```

* Left/right/forward/backward response
    ```
    001B 01
    ```

### Schedule Response
The result is plain text representing hexadecimal data (no spaces).

Example (every day at 3am):

```
        Monday
        |    Tuesday
        |    |    Wednesday
        |    |    |   Thursday
        |    |    |    |    Friday
        |    |    |    |    |    Saturday
        |    |    |    |    |    |    Sunday
        |__  |__  |__  |__  |__  |__  |__
     ?? |  \ |  \ |  \ |  \ |  \ |  \ |  \
000D 7F 0300 0300 0300 0300 0300 0300 0300
```

Days start with Monday and end with Sunday.

Each day is of the form:

```
Hour (1 byte)
| Minute (1 byte)
| |
AAaa
```

For example, `0300` is 3am; `030F` is 3:15am, `031E` is 3:30am, etc.

Note that the iAquaLink app requires that the minute be in 15-minute increments.

### Status Response
The result is plain text representing hexadecimal data (no spaces).

Examples (???):

```
     State
     |  Error code ???
     |  |  Cleaning mode
     |  |  |  Minutes remaining
     |  |  |  |  Uptime (minutes) ???
     |  |  |  |  |      Runtime (minutes) ???
     |  |  |  |  |____  |____
     |\ |\ |\ |\ |    \ |    \ ?????? ??????
0011 04 00 0B 73 09C305 B3FD01 1F4309 0F4570
0011 04 00 0B 00 39CF05 820502 1F4309 0F4570 [9:37pm]
0011 0C 00 0B 00 3ACF05 4E0602 1F4309 0F4570 [9:38pm]
0011 03 00 0B D2 3BCF05 4E0602 1F4309 0F4570 [9:39pm]
0011 01 00 0B D2 0EC305 B3FD01 1F4309 0F4570
0011 04 00 0B 84 AFC605 6F0002 1F4309 0F4570 - Deep - floor and walls (high)
0011 02 00 08 63 B1C605 6F0002 1F4309 0F4570 - Quick - floor only (standard)
0011 02 00 0C 36 B2C605 6F0002 1F4309 0F4570 - Waterline only (standard)
0011 02 00 09 6D B3C605 6F0002 1F4309 0F4570 - Custom - floor (high)
0011 02 00 0A 9F B4C605 6F0002 1F4309 0F4570 - Cusomm - floor and walls (standard)
0011 02 00 0D 40 B5C605 6F0002 1F4309 0F4570 - Custom - waterline (high)
0011 02 00 0B CC BCC605 6F0002 1F4309 0F4570
0011 03 00 0B D2 2ACA05 210302 1F4309 0F4570 - Finished
0011 03 00 0B D2 40CA05 210302 1F4309 0F4570
0011 03 00 0B D2 44CA05 210302 1F4309 0F4570 - Finished [12:07am]
0011 03 00 0B D2 45CA05 210302 1F4309 0F4570 - Finished [12:08am]
0011 03 00 0B D2 46CA05 210302 1F4309 0F4570 - Finished [12:09am]
0011 0D 08 0B D2 B3D105 180702 1F4309 0F4570 - Error - out of water [8:19am]
0011 03 00 0B D2 8DD305 E40702 1F4309 0F4570 [4:21pm]
0011 02 00 0B D1 8FD305 E40702 1F4309 000000 [4:23pm]
0011 02 00 0B D0 90D305 E40702 1F4309 0F4570 [4:24pm]
0011 03 00 0B D2 2FEC05 F71202 1F4309 0F4570 - Finished [2:59am]
0011 02 00 0B D1 30EC05 F71202 1F4309 0F4570 - Started [3:00am]
0011 0D 08 0B D2 31EC05 A51302 1F4309 0F4570 - Error - out of water [3:01am]
0011 0E 08 0B D2 3BEC05 A51302 1F4309 0F4570 - Error - ??? [3:11am]
0011 0E 05 0B D2 8D4707 0CE202 1F4309 0F4570 - Error - drive motor consumption right
0011 0E 0A 0B D2 885507 25E302 1F4309 000000 - Error - communication
0011 04 00 0B 03 87DC07 D80F00 1F4309 0F4580 [after replacing the motor block]
0011 0C 00 0B 00 8CDC07 D80F00 1F4309 0F4580 [as it's finishing up]
0011 03 00 0B D2 8CDC07 A21000 1F4309 0F4580 [after it finishes]
```

State:

* `01`; stopped (manually?)
* `02`; running
* `03`; finished (on its own?)
* `04`; running
* `0A`; lift system
* `0B`; remote control
* `OC`; finishing???
* `0D`; error - first 10 minutes???
* `OE`; error - after 10 minutes???

I've seen it transition from `02` to `04` 10 minutes into a scheduled cleaning and 10 minutes into a manual cleaning.

I've seen it transition from `OD` to `OE` 10 minutes into a scheduled cleaning when the robot was out of the water.

I've seen it transition from `04` to `0C` to `03` over the span of 3 minutes.

The runtime only appears to update after a cleaning cycle completes.

Error code ???:

* `00`; no error
* `04`; pump motor consumption
* `05`; drive motor consumption right
* `08`; out of water
* `0a`; communication

Cleaning mode:

* `08`; floor (standard)
* `09`; floor (high) ["custom" in the app]
* `0A`; floor and walls (standard) ["custom" in the app]
* `0B`; floor and walls (high)
* `0C`; waterline (standard)
* `0D`; waterline (high) ["custom" in the app]

## Development

### Traffic Capture with `mitmproxy`
If you'd like to help get your particular pool robot working (or help with a subset of functionality that isn't properly supported), set up an `mitmproxy` and configure your phone's wifi network to use the proxy.
This will allow you to capture (and decrypt) all of the traffic that goes to and from the Zodiac/iAquaLink APIs.

For information about `mitmproxy`, see: https://mitmproxy.org/

When using `mitmproxy`, please only perform iAquaLink operations and then immediately remove the proxy settings.
I don't want you to accidentally capture your passwords and credentials from other pieces of software.

If possible, only use a spare phone (or an emulator) that only has iAquaLink installed.

The ideal workflow is the following:

1. Log out of your iAquaLink account.
2. Start `mitmproxy`.
3. Configure your phone's wifi to use the proxy.
4. Open iAquaLink.
5. Login.
6. Perform a single action.
7. Stop `mitmproxy` and save the results.
8. Configure your phone's wifi to not use the proxy anymore.

This way, the traffic captured only has the login operation and a single operation.
If you're going to share this capture with someone, please _change your password_ after completing it (or change it before you start and then change it back when you're done).

If you perfom multiple operations, please write down which operations you performed in the order that you performed them.
