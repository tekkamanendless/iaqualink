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

## Schedule format
The result is plain text representing hexadecimal data.

Example (every day at 3am):

```
      Monday
      |   Tuesday
      |   |   Wednesday
      |   |   |   Thursday
      |   |   |   |   Friday 
      |   |   |   |   |   Saturday
      |   |   |   |   |   |   Sunday
      |__ |__ |__ |__ |__ |__ |__
??????|  \|  \|  \|  \|  \|  \|  \
000D7F0300030003000300030003000300
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

## Status format
The result is plain text representing hexadecimal data.

Example (???):

```
    State
	|   Cleaning mode
    |   | Minutes remaining
    |   | |
????|\??|\|\????????????????????????
001104000B7309C305B3FD011F43090F4570
001101000BD20EC305B3FD011F43090F4570
001104000B84AFC6056F00021F43090F4570 - Deep - floor and walls (high)
001102000863B1C6056F00021F43090F4570 - Quick - floor only (standard)
001102000C36B2C6056F00021F43090F4570 - Waterline only (standard)
00110200096DB3C6056F00021F43090F4570 - Custom - floor (high)
001102000A9FB4C6056F00021F43090F4570 - Cusomm - floor and walls (standard)
001102000D40B5C6056F00021F43090F4570 - Custom - waterline (high)
001102000BCCBCC6056F00021F43090F4570
                      ^^
                      Day of week?
```

State:

* `01`; stopped
* `02`; running (???)
* `04`; running (???)
* `0B`; remote control

Cleaning mode:

* `08`; floor (standard)
* `09`; floor (high) [custom]
* `0A`; floor and walls (standard) [custom]
* `0B`; floor and walls (high)
* `0C`; waterline (standard)
* `0D`; waterline (high) [custom]

