import json, strutils, base64, times, jwt/crypto

proc encodeBase64url(s: string): string =
  result = base64.encode(s)
  while result[^1] == '=':
    result.setLen(result.len - 1)
  return result.replace('+', '-').replace('/', '_')

type
  InvalidToken* = object of Exception

proc sign(alg, headerB64, claimB64, secret: string): string =
  var token = ""
  token.add headerB64
  token.add "."
  token.add claimB64
  if alg != "none":
    var signature = 
      case alg:       
        of "HS256": signHMAC(token, secret, EVP_sha256())
        of "HS384": signHMAC(token, secret, EVP_sha384())
        of "HS512": signHMAC(token, secret, EVP_sha512())
        of "RS256": signPEM(token, secret, EVP_sha256())    
        of "RS384": signPEM(token, secret, EVP_sha384())   
        of "RS512": signPEM(token, secret, EVP_sha512())
        else:
          raise newException(ValueError, "Algorithm " & alg & " not supported.")
    token.add "."
    token.add encodeBase64url(signature)
  return token

proc claim*(token: string): JsonNode =
  ## Gets the claim from a token
  let arr = token.split(".")  
  parseJson(base64.decode(arr[1]))

proc sign*(header: JsonNode, claim: JsonNode, secret: string): string =
  ## Signs a the claim with the secret
  let headerB64 = encodeBase64url($header)
  let claimB64 = encodeBase64url($claim)
  let alg = header["alg"].getStr()
  sign(alg, headerB64, claimB64, secret)

proc verifyEx*(token, secret: string, algs: seq[string]) =
  ## Verifies the token is valid, throwing exception if not.
  let arr = token.split(".")
  let header = parseJson(base64.decode(arr[0]))
  
  # check algorithm
  let alg = header["alg"].getStr()
  if alg notin algs:
    raise newException(InvalidToken, "Algorithm not supported.")
  
  # check signature
  let other = sign(alg, arr[0], arr[1], secret)
  if token != other:
    raise newException(InvalidToken, "Token verification failed.")

  # check time claims
  let claim = token.claim
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
