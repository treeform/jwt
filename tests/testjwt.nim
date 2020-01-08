import json, times, unittest
from times import nil

import jwt

let pubTestKey = """
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnzyis1ZjfNB0bBgKFMSv
vkTtwlvBsaJq7S5wA+kzeVOVpVWwkWdVha4s38XM/pa/yr47av7+z3VTmvDRyAHc
aT92whREFpLv9cj5lTeJSibyr/Mrm/YtjCZVWgaOYIhwrXwKLqPr/11inWsAkfIy
tvHWTxZYEcXLgAXFuUuaS3uF9gEiNQwzGTU1v0FqkqTBr4B8nW3HCN47XUu0t8Y0
e+lf4s4OxQawWD79J9/5d3Ry0vbV3Am1FtGJiJvOwRsIfVChDpYStTcHTCMqtvWb
V6L11BWkpzGXSW4Hv43qa+GSYOD2QU68Mb59oSk2OB+BtOLpJofmbGEGgvmwyCI9
MwIDAQAB
-----END PUBLIC KEY-----
"""

let pivTestKey = """
-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAnzyis1ZjfNB0bBgKFMSvvkTtwlvBsaJq7S5wA+kzeVOVpVWw
kWdVha4s38XM/pa/yr47av7+z3VTmvDRyAHcaT92whREFpLv9cj5lTeJSibyr/Mr
m/YtjCZVWgaOYIhwrXwKLqPr/11inWsAkfIytvHWTxZYEcXLgAXFuUuaS3uF9gEi
NQwzGTU1v0FqkqTBr4B8nW3HCN47XUu0t8Y0e+lf4s4OxQawWD79J9/5d3Ry0vbV
3Am1FtGJiJvOwRsIfVChDpYStTcHTCMqtvWbV6L11BWkpzGXSW4Hv43qa+GSYOD2
QU68Mb59oSk2OB+BtOLpJofmbGEGgvmwyCI9MwIDAQABAoIBACiARq2wkltjtcjs
kFvZ7w1JAORHbEufEO1Eu27zOIlqbgyAcAl7q+/1bip4Z/x1IVES84/yTaM8p0go
amMhvgry/mS8vNi1BN2SAZEnb/7xSxbflb70bX9RHLJqKnp5GZe2jexw+wyXlwaM
+bclUCrh9e1ltH7IvUrRrQnFJfh+is1fRon9Co9Li0GwoN0x0byrrngU8Ak3Y6D9
D8GjQA4Elm94ST3izJv8iCOLSDBmzsPsXfcCUZfmTfZ5DbUDMbMxRnSo3nQeoKGC
0Lj9FkWcfmLcpGlSXTO+Ww1L7EGq+PT3NtRae1FZPwjddQ1/4V905kyQFLamAA5Y
lSpE2wkCgYEAy1OPLQcZt4NQnQzPz2SBJqQN2P5u3vXl+zNVKP8w4eBv0vWuJJF+
hkGNnSxXQrTkvDOIUddSKOzHHgSg4nY6K02ecyT0PPm/UZvtRpWrnBjcEVtHEJNp
bU9pLD5iZ0J9sbzPU/LxPmuAP2Bs8JmTn6aFRspFrP7W0s1Nmk2jsm0CgYEAyH0X
+jpoqxj4efZfkUrg5GbSEhf+dZglf0tTOA5bVg8IYwtmNk/pniLG/zI7c+GlTc9B
BwfMr59EzBq/eFMI7+LgXaVUsM/sS4Ry+yeK6SJx/otIMWtDfqxsLD8CPMCRvecC
2Pip4uSgrl0MOebl9XKp57GoaUWRWRHqwV4Y6h8CgYAZhI4mh4qZtnhKjY4TKDjx
QYufXSdLAi9v3FxmvchDwOgn4L+PRVdMwDNms2bsL0m5uPn104EzM6w1vzz1zwKz
5pTpPI0OjgWN13Tq8+PKvm/4Ga2MjgOgPWQkslulO/oMcXbPwWC3hcRdr9tcQtn9
Imf9n2spL/6EDFId+Hp/7QKBgAqlWdiXsWckdE1Fn91/NGHsc8syKvjjk1onDcw0
NvVi5vcba9oGdElJX3e9mxqUKMrw7msJJv1MX8LWyMQC5L6YNYHDfbPF1q5L4i8j
8mRex97UVokJQRRA452V2vCO6S5ETgpnad36de3MUxHgCOX3qL382Qx9/THVmbma
3YfRAoGAUxL/Eu5yvMK8SAt/dJK6FedngcM3JEFNplmtLYVLWhkIlNRGDwkg3I5K
y18Ae9n7dHVueyslrb6weq7dTkYDi3iOYRW8HRkIQh06wEdbxt0shTzAJvvCQfrB
jg/3747WSsf/zBTcHihTRBdAv6OmdhV4/dD5YBfLAkLrd+mX7iE=
-----END RSA PRIVATE KEY-----
"""

suite "Token tests":
  test "test none sucess":
    let 
      secret = "secret"
      token = sign(
        header = %*{
          "typ":"JWT",
          "alg":"none"
        },
        claim = %*{},
        secret = secret
      )
    assert token.verify(secret) == true

  test "test none fail":
    let 
      secret = "secret"
      token = sign(
        header = %*{
          "typ":"JWT",
          "alg":"none"
        },
        claim = %*{},
        secret = secret
      )      
    var tokenBad = token & "j"
    assert tokenBad.verify(secret) == false

  test "test HS256 sucess":
    let 
      secret = "secret"
      token = sign(
        header = %*{
          "typ":"JWT",
          "alg":"HS256"
        },
        claim = %*{},
        secret = secret
      )
    assert token.verify(secret) == true

  test "test HS256 fail":
    let 
      secret = "secret"
      token = sign(
        header = %*{
          "typ":"JWT",
          "alg":"HS256"
        },
        claim = %*{},
        secret = secret
      )
    var tokenBad = token & "j"
    assert tokenBad.verify(secret) == false

  test "NBF Check":
    let
      secret = "secret"
      now = epochTime() + 60
      token = sign(
        header = %*{
          "typ":"JWT",
          "alg":"HS256"
        },
        claim = %*{
          "nbf": now
        },
        secret = secret
      )    
    assert token.verify(secret) == false

  test "EXP Check":
    let
      secret = "secret"
      now = epochTime() - 60
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
    assert token.verify(secret) == false

  test "claim":
    var token: string
    token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMiIsIm5hbWUiOiJOb3RoaW5nIn0.rbyfHhJvsQ7_VWx6-tD1HZ9GklcCjwsl-gSqYwTzQSI"
    assert token.claim == %*{"sub":"12","name":"Nothing"}
    token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxMiIsIm5hbWUiOiJTdXBlciBjb29sIiwiYWRtaW4iOmZhbHNlLCJtc2ciOiJPTUcgaXQgd29ya3MhIn0.lEhL5eZMUPaIA-9BMBWQeJj2D5RMfwY1AtKCcHgvVC2MxuWx8U-gzyrxbfeiw6mDB6L-RgDhtO3Hc0XpJ_JZxcsK-ONNWjz9WMww5uMtJqRSsJxClt8qYCOSXabLW_Ggstdxfp88atunmCcJkc6v2mnR3kRBsbtXxdUki5Qp94Tt4qA3P4mhsGMGz9QJp067zDsPDP9mnWyjarGz6z2d-YcGw6FEM-qWSLRuKhBOOtZinMdvAT8Bp9kA6AYkXg3ds5xfzfoLyKxC-mcZ87VzOpfqCCo8ez7NYxb6D5itWgACFZc7uLqNn-5bE0x9aCOEQiyYf54PLLXsA5Xnhh2rFA"
    assert token.claim == %*{"sub":"12","name":"Super cool","admin":false,"msg":"OMG it works!"}

  test "check HS256":
    var token: string
    token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.TXEWPLzMK8zBQ_HwfVbY3MVJWM1byFJysqdYXjsslTY"
    assert token.verify("foobar")
    token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.hEAzJ-JWP5s23Z3MeXMHQBsGfuI6vYNVwVBT2nx96iQ"
    assert token.verify("nana")
    token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMiIsIm5hbWUiOiJOb3RoaW5nIn0.vupkVR4_tio-BOPNn7oslQeXXRz5YAbnRbAdgaNi-Rc"
    assert token.verify("super")
    token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMiIsIm5hbWUiOiJOb3RoaW5nIn0.rbyfHhJvsQ7_VWx6-tD1HZ9GklcCjwsl-gSqYwTzQSI"
    assert token.verify("?")

  test "check HS384":
    var token: string
    token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzM4NCJ9.eyJzdWIiOiIxMiIsIm5hbWUiOiJTdXBlciBjb29sIiwiYWRtaW4iOmZhbHNlLCJtc2ciOiJPTUcgaXQgd29ya3MhIn0.K8SWbvLDsZyGn2bzwOMvGhxlaUc1QYZSMpOag6X4gfQyDW-EemIajYowpmUbwhnC"
    token.verifyEx("?", @["HS384"])

  test "check HS512":
    var token: string
    token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzUxMiJ9.eyJzdWIiOiIxMiIsIm5hbWUiOiJTdXBlciBjb29sIiwiYWRtaW4iOmZhbHNlLCJtc2ciOiJPTUcgaXQgd29ya3MhIn0.IJwn4dWp-dQWwWmAn5WDgbOdXb6-ddoLsrYizBsR7cRHd4T-_Tyt8qfJQsB3ZfKGLqG159c_cphseA_hGJyc8w"
    token.verifyEx("?", @["HS512"])
    
 
  test "check RS256":
    var token: string
    token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.POstGetfAytaZS82wHcjoTyoqhMyxXiWdR7Nn7A29DNSl0EiXLdwJ6xC6AfgZWF1bOsS_TuYI3OG85AmiExREkrS6tDfTQ2B3WXlrr-wp5AokiRbz3_oB4OxG-W9KcEEbDRcZc0nH3L7LzYptiy1PtAylQGxHTWZXtGz4ht0bAecBgmpdgXMguEIcoqPJ1n3pIWk_dUZegpqx0Lka21H6XxUTxiy8OcaarA8zdnPUnV6AmNP3ecFawIFYdvJB_cm-GvpCSbr8G8y_Mllj8f4x9nBH8pQux89_6gUY618iYv7tuPWBFfEbLxtF2pZS6YC1aSfLQxeNe8djT9YjpvRZA"
    token.verifyEx(pivTestKey, @["RS256"])
    token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxMiIsIm5hbWUiOiJTdXBlciBjb29sIiwiYWRtaW4iOmZhbHNlfQ.ciSgT1wsyXegBALqKXDlua7JrSFknwOH3Q3JbJ8jJrxBSbq15H7jsIopvXwmQpyWKAyGHWCpUPKULOQ026580zEaFyGUId9W9PQDebJGSIlkLXKynhfYgM6ejBotFnAoMK-ZK4B47DhcKEsCx8bx-huApCGqVtaLTS9cDcvGzKxo1k-dAGx7PjTJwNxdD9VFHkSxBknVJMMbsH9kBHgytCtt690hLVHygTLD8QFT3iuGUGRtPgC-SIotF15LK7IncALS6RITPMbTwtE_2YJ8ViMtJ2R8Gz7FXk82mdpGXVRWXiIaD4GuPRnAgyI7gECWyuPkBIVRXJBs2R4u8eBvxg"
    token.verifyEx(pivTestKey, @["RS256"])
    token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxMiIsIm5hbWUiOiJTdXBlciBjb29sIiwiYWRtaW4iOmZhbHNlLCJtc2ciOiJPTUcgaXQgd29ya3MhIn0.lEhL5eZMUPaIA-9BMBWQeJj2D5RMfwY1AtKCcHgvVC2MxuWx8U-gzyrxbfeiw6mDB6L-RgDhtO3Hc0XpJ_JZxcsK-ONNWjz9WMww5uMtJqRSsJxClt8qYCOSXabLW_Ggstdxfp88atunmCcJkc6v2mnR3kRBsbtXxdUki5Qp94Tt4qA3P4mhsGMGz9QJp067zDsPDP9mnWyjarGz6z2d-YcGw6FEM-qWSLRuKhBOOtZinMdvAT8Bp9kA6AYkXg3ds5xfzfoLyKxC-mcZ87VzOpfqCCo8ez7NYxb6D5itWgACFZc7uLqNn-5bE0x9aCOEQiyYf54PLLXsA5Xnhh2rFA"
    token.verifyEx(pivTestKey, @["RS256"])

  test "check RS384":
    var token: string
    token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzM4NCJ9.eyJzdWIiOiIxMiIsIm5hbWUiOiJTdXBlciBjb29sIiwiYWRtaW4iOmZhbHNlLCJtc2ciOiJPTUcgaXQgd29ya3MhIn0.XNv1SMPVKqH7zi2LBOkBGbSr0HnooigTKU2_UUG1XkwdW9tw0JrhJVUh5LEplHf76fb3NqbIARNV2IiXtXZFh7sWAzg5wE_puQFZG0CRN_KbjhKLAgtJmykXPGIWd0gmhCiFqPg_5YH9NqXdEReUvy3lqJhNWstt8ff-Jm74xrxgM6VScR4m0qDSYOgZFVxkKo-aYbVZoPRhsccC8KYTK3htYJpppv-6XFSf3TB9kWJc4WtoBABP-qdBlL6kzrpYf0d4CY_pFInFPikugec3Yvliind7Fy1Fy-uCiRe7hVGrhrh0UU4TnpY7uvtfZQc_NKdvGyh7oowHAVZYYWv7ow"
    token.verifyEx(pivTestKey, @["RS384"])
  
  test "check RS512":
    var token: string
    token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzUxMiJ9.eyJzdWIiOiIxMiIsIm5hbWUiOiJTdXBlciBjb29sIiwiYWRtaW4iOmZhbHNlLCJtc2ciOiJPTUcgaXQgd29ya3MhIn0.R4jyWyrgRoyAaYze7eIx4dosu_4Kvrt2ZY7tLzEaf5lzBTbCpFnjZWDfqgvVn6W0pKxpyP0Is23IzXw3lTMfBUDPbYbFHpaqr1h6yjxXgBYHJBrJ6GVBTNVxhlsZ02rIPXJXz7DqhbOtRL6loa5aZrMNQBZnvQ1VgluVIkpaIB1o7-zV_tdmOK6eibyiFLsf7tcGqhmPNkrV9Cv-gTpFWGCjEU2DmoFC4No9GGWn1srB7ZdWhEuw6tTbK7PYSq0z6K4GaZNXiRbpNj45N0Kw8QVFcUJO457bR9Q0NWtkbnZupVBfjjtBrHNZW47IbkLApLYOibJU8oQAbkESnbVdDQ"
    token.verifyEx(pivTestKey, @["RS512"])
    
