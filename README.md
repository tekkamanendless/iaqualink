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
    |     Minutes remaining
    |     |
????|\????|\????????????????????????
001104000B7309C305B3FD011F43090F4570
001101000BD20EC305B3FD011F43090F4570
```

State:

* `01`; stopped
* `02`; running (???)
* `04`; running (???)
* `0B`; remote control

