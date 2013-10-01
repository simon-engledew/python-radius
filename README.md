Python Radius is a pure python radius client which supports two important extension RFCs:

## RFC2869 / 5.14 (http://www.ietf.org/rfc/rfc2869.txt)
The Message-Authenticator extension - authenticating a radius packet using an MD5 HMAC

and

## RFC5997 (http://tools.ietf.org/html/rfc5997)

Use of Status-Server Packets in the Remote Authentication Dial In User Service (RADIUS) Protocol - checking a radius server is alive without generating spurious log entries.


## Usage:

```
with Radius.connect('10.0.0.1', 1812, 'secret') as connection:
    print connection.ping()
    print connection.authenticate('username', 'password')
```