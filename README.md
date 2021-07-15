# iaqualink
Go package for talking with iAquaLink pool robots.

## Endpoints

### `/devices/${device}/execute_read_command.json`

Query parameters:

* `api_key`: `EOOEMOW4YR6QNB07`
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

* `0A` `<command>` `<subcommand>`

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
Start/clear error response

```
0012 01
```

Add/subtract time response

```
0013 01
```

Lift system, lift/stop response

```
0017 01
```

Left/right/forward/backward response

```
001B 01
```

### Schedule format
The result is plain text representing hexadecimal data.

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

### Status format
The result is plain text representing hexadecimal data.

Example (???):

```
     State
     |     Cleaning mode
     |     |  Minutes remaining
     |     |  |
     |\ ?? |\ |\ ???? ?? ???? ?? ????????????
0011 04 00 0B 73 09C3 05 B3FD 01 1F43090F4570
0011 01 00 0B D2 0EC3 05 B3FD 01 1F43090F4570
0011 04 00 0B 84 AFC6 05 6F00 02 1F43090F4570 - Deep - floor and walls (high)
0011 02 00 08 63 B1C6 05 6F00 02 1F43090F4570 - Quick - floor only (standard)
0011 02 00 0C 36 B2C6 05 6F00 02 1F43090F4570 - Waterline only (standard)
0011 02 00 09 6D B3C6 05 6F00 02 1F43090F4570 - Custom - floor (high)
0011 02 00 0A 9F B4C6 05 6F00 02 1F43090F4570 - Cusomm - floor and walls (standard)
0011 02 00 0D 40 B5C6 05 6F00 02 1F43090F4570 - Custom - waterline (high)
0011 02 00 0B CC BCC6 05 6F00 02 1F43090F4570
0011 03 00 0B D2 2ACA 05 2103 02 1F43090F4570 - Finished
0011 03 00 0B D2 40CA 05 2103 02 1F43090F4570
0011 03 00 0B D2 44CA 05 2103 02 1F43090F4570 - Finished [12:07am]
0011 03 00 0B D2 45CA 05 2103 02 1F43090F4570 - Finished [12:08am]
0011 03 00 0B D2 46CA 05 2103 02 1F43090F4570 - Finished [12:09am]
0011 0D 08 0B D2 B3D1 05 1807 02 1F43090F4570 - Error - out of water [8:19am]
                 ^^^^
                 Uptime?
```

State:

* `01`; stopped (manually?)
* `02`; running
* `03`; finished (on its own?)
* `04`; running
* `0A`; lift system
* `0B`; remote control
* `0D`; error - out of water

I've seen it transition from `02` to `04` 10 minutes into a scheduled cleaning and 10 minutes into a manual cleaning.

Cleaning mode:

* `08`; floor (standard)
* `09`; floor (high) [custom]
* `0A`; floor and walls (standard) [custom]
* `0B`; floor and walls (high)
* `0C`; waterline (standard)
* `0D`; waterline (high) [custom]

