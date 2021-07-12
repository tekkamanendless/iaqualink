# iaqualink
Go package for talking with iAquaLink pool robots.

## Schedule format
The result is plain text representing hexadecimal data.

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

