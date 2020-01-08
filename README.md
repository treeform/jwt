# JWT Implementation for Nim


This is a implementation of [JSON Web Tokens](https://jwt.io/) for Nim. This is based on the work of [Yuriy Glukhov](https://github.com/yglukhov/nim-jwt) but differs in API.

## Examples

Create a token:

```nim
token = sign(
  header = %*{
    "typ":"JWT",
    "alg":"HS256"
  },
  claim = %*{
    "exp": now
  },
  secret = secret
)  
```

Verify a token:

```nim
try:
  token.verifyEx(pivTestKey, @["RS256"])
  ...
except:
  ...
```

or

```nim
if token.verify(pivTestKey, @["RS256"]):
  ...
```


Get token's claim:
```nim
token.claim
```

## Supported

Algorithms:
* none
* HS256
* HS384
* HS512
* RS256
* RS384
* RS512

Claims:
* nbf - Not before timestamp
* exp - Expire after timestamp



## Getting google api oauth2 token


```nim
import jwt, json, times, httpclient, cgi

const email = "username@api-12345-12345.iam.gserviceaccount.com" # Acquired from google api console
const scope = "https://www.googleapis.com/auth/androidpublisher" # Define needed scope
const privateKey = """
-----BEGIN PRIVATE KEY-----
The key should be Acquired from google api console
-----END PRIVATE KEY-----
"""

var token = jwt.sign(
  header = %*{
    "alg": "RS256", 
    "typ": "JWT"
  },
  claim = %*{
    "iss": conn.email,
    "scope": scope,
    "aud": "https://www.googleapis.com/oauth2/v4/token",
    "exp": int(epochTime() + 60 * 60),
    "iat": int(epochTime()) 
  },
  secret = conn.privateKey
)

let postdata = "grant_type=" & encodeUrl("urn:ietf:params:oauth:grant-type:jwt-bearer") & "&assertion=" & token

proc request(url: string, body: string): string =
  var client = newHttpClient()
  client.headers = newHttpHeaders({ "Content-Length": $body.len, "Content-Type": "application/x-www-form-urlencoded" })
  result = client.postContent(url, body)
  client.close()

let resp = request("https://www.googleapis.com/oauth2/v4/token", postdata).parseJson()
echo "Access token is: ", resp["access_token"].str
```

## Troubleshooting

This library requires a recent version of libcrypto. Specifically the one that has `EVP_DigestSign*` functions.
