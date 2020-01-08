import json, nimcrypto, strutils, base64, times, private/crypto

proc encodeBase64url(s: string): string =
  result = base64.encode(s)
  while result[^1] == '=':
    result.setLen(result.len - 1)
  return result.replace('+', '-').replace('/', '_')

proc decodeBase64url(s: string): string =
  base64.decode(s.replace('-', '+').replace('_', '/'))

type
  InvalidToken* = object of Exception

template HS(shaXXX: untyped, token, secret: string): string =
  var hmac: HMAC[shaXXX]
  hmac.init(cast[ptr byte](unsafeAddr secret[0]), uint secret.len)
  hmac.update(token)
  var s = ""
  for num in hmac.finish().data:
    s.add char(num)
  encodeBase64url(s)

template RS(shaXXX: untyped, token, secret: string): string =
  let res = signPEM(token, secret, shaXXX, crypto.EVP_PKEY_RSA)
  var s = ""
  for num in res:
    s.add char(num)
  encodeBase64url(s)

proc sign(alg, headerB64, claimB64, secret: string): string =
  var token = ""
  token.add headerB64
  token.add "."
  token.add claimB64
  var signedB64 = 
    case alg: 
      of "none": ""
      of "HS256": HS(sha256, token, secret)
      of "HS384": HS(sha384, token, secret)
      of "HS512": HS(sha512, token, secret)
      of "RS256": RS(crypto.EVP_sha256(), token, secret)    
      of "RS384": RS(crypto.EVP_sha384(), token, secret)   
      of "RS512": RS(crypto.EVP_sha512(), token, secret)
      else:
        raise newException(ValueError, "Algorithm " & alg & " not supported.")
  if signedB64.len > 0:
    token.add "."
    token.add signedB64
  return token

proc sign*(header: JsonNode, claim: JsonNode, secret: string): string =
  let headerB64 = encodeBase64url($header)
  let claimB64 = encodeBase64url($claim)
  let alg = header["alg"].getStr()
  sign(alg, headerB64, claimB64, secret)

proc verifyEx*(token, secret: string, algs: seq[string]) =
  ## Verifies the token is valid, throwing exception if not.
  let arr = token.split(".")
  let header = parseJson(decodeBase64url(arr[0]))
  let alg = header["alg"].getStr()
  if alg notin algs:
    raise newException(InvalidToken, "Algorithm not supported.")
  let other = sign(alg, arr[0], arr[1], secret)
  if token != other:
    raise newException(InvalidToken, "Token verification failed.")
  # time claims
  let claim = parseJson(decodeBase64url(arr[1]))

  let now = epochTime()

  if claim.hasKey("nbf"):
    let nbf = claim["nbf"].getFloat()
    if now < nbf:
      raise newException(InvalidToken, "Token can't be used yet.")

  if claim.hasKey("exp"):
    let exp = claim["exp"].getFloat()
    if now > exp :
      raise newException(InvalidToken, "Token has expired.")
  
proc verify*(token, secret: string, algs: seq[string]): bool =
  ## Verifies the token is valid, returns a bool.
  try:
    verifyEx(token, secret, algs)
    return true
  except:
    return false

proc verify*(token, secret: string): bool =
  ## Verifies the token is valid. 
  verify(token, secret, @["none", "HS256"])

proc claim*(token: string): JsonNode =
  ## Gets the claim from a token
  let arr = token.split(".")  
  parseJson(decodeBase64url(arr[1]))
