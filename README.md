[![Go Report Card](https://goreportcard.com/badge/github.com/tekkamanendless/iaqualink)](https://goreportcard.com/report/github.com/tekkamanendless/iaqualink)
[![GoDoc](https://godoc.org/github.com/tekkamanendless/iaqualink?status.svg)](https://godoc.org/github.com/tekkamanendless/iaqualink)

# iaqualink
Go package for talking with iAquaLink pool robots.

This package has been built by reverse-engineering the iAquaLink HTTP protocol using `mitmproxy`.

## Tested With

* Polaris P965IQ

## Zodiac API
Base: https://prod.zodiac-io.com

### `/users/v1/login`
This logs you into the Zodiac API and provides you with a user ID and authentication token.
These will be used by the iAquaLink API.

JSON body:

* `apiKey`: `EOOEMOW4YR6QNB07`; this appears to be constant
* `email`; your e-mail address
* `password`; your password

JSON response (relevant subset):

* `authenticationToken`; this is the authentication token
* `id`; this is the user ID

## iAquaLink API
Base: https://r-api.iaqualink.net

### `/devices.json`
This lists the devices on your account.
You'll need the device ID for any device-related endpoints.

Query parameters:

* `api_key`: `EOOEMOW4YR6QNB07`; this appears to be constant
* `authentication_token`; your authentication token
* `user_id`; your user ID

### `/devices/${device}/execute_read_command.json`
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

## Responses
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
```

State:

* `01`; stopped (manually?)
* `02`; running
* `03`; finished (on its own?)
* `04`; running
* `0A`; lift system
* `0B`; remote control
* `OC`; ???
* `0D`; error - first 10 minutes???
* `OE`; error - after 10 minutes???

I've seen it transition from `02` to `04` 10 minutes into a scheduled cleaning and 10 minutes into a manual cleaning.

I've seen it transition from `OD` to `OE` 10 minutes into a scheduled cleaning when the robot was out of the water.

I've seen it transition from `04` to `0C` to `03` over the span of 3 minutes.

Error code ???:

* `00`; no error
* `05`; drive motor consumption right
* `08`; out of water

Cleaning mode:

* `08`; floor (standard)
* `09`; floor (high) ["custom" in the app]
* `0A`; floor and walls (standard) ["custom" in the app]
* `0B`; floor and walls (high)
* `0C`; waterline (standard)
* `0D`; waterline (high) ["custom" in the app]
