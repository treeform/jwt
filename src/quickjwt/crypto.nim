import openssl

when not defined(EVP_MD) and not defined(EVP_MD_CTX) and not defined(EVP_PKEY_CTX) and not defined(ENGINE):
  type
    EVP_MD = SslPtr
    EVP_MD_CTX = SslPtr
    EVP_PKEY_CTX = SslPtr
    ENGINE = SslPtr

  # sha types
  proc EVP_sha256*(): EVP_MD {.cdecl, importc.}
  proc EVP_sha384*(): EVP_MD {.cdecl, importc.}
  proc EVP_sha512*(): EVP_MD {.cdecl, importc.}

  # hmac functions
  proc HMAC(evp_md: EVP_MD; key: pointer; key_len: cint; d: cstring; n: csize_t; md: cstring; md_len: ptr cuint): cstring {.cdecl, importc.}

  # RSA key functions
  proc PEM_read_bio_PrivateKey(bp: BIO, x: ptr EVP_PKEY, cb: pointer, u: pointer): EVP_PKEY {.cdecl, importc.}
  proc EVP_PKEY_free(p: EVP_PKEY)  {.cdecl, importc.}
  proc EVP_DigestSignInit(ctx: EVP_MD_CTX, pctx: ptr EVP_PKEY_CTX, typ: EVP_MD, e: ENGINE, pkey: EVP_PKEY): cint {.cdecl, importc.}
  proc EVP_DigestUpdate(ctx: EVP_MD_CTX, data: pointer, len: cuint): cint {.cdecl, importc.}
  proc EVP_DigestSignFinal(ctx: EVP_MD_CTX, data: pointer, len: ptr csize_t): cint {.cdecl, importc.}
  proc EVP_PKEY_CTX_new(pkey: EVP_PKEY, e: ENGINE): EVP_PKEY_CTX {.cdecl, importc.}
  proc EVP_PKEY_CTX_free(pkeyCtx: EVP_PKEY_CTX) {.cdecl, importc.}
  proc EVP_PKEY_sign_init(c: EVP_PKEY_CTX): cint {.cdecl, importc.}

  when defined(macosx) or defined(windows):
    proc EVP_MD_CTX_create(): EVP_MD_CTX {.cdecl, importc.}
    proc EVP_MD_CTX_destroy(ctx: EVP_MD_CTX) {.cdecl, importc.}
  else:
    # some times you will need this instead:
    proc EVP_MD_CTX_create(): EVP_MD_CTX {.cdecl, importc: "EVP_MD_CTX_new".}
    proc EVP_MD_CTX_destroy(ctx: EVP_MD_CTX) {.cdecl, importc: "EVP_MD_CTX_free".}

  when not declared(BIO_new_mem_buf) or defined(windows):
    proc BIO_new_mem_buf(data: pointer, len: cint): BIO {.cdecl, importc.}

proc signHMAC*(token, secret: string, alg: EVP_MD): string =
  var
    signature = newString(64)
    signatureLen: cuint
  discard HMAC(
    alg,
    unsafeAddr secret[0], 8,
    token.cstring, token.len.csize_t,
    unsafeAddr signature[0], addr signatureLen
  )
  signature.setLen(signatureLen)
  signature

proc signPem*(data, key: string, alg: EVP_MD): string =
  var
    bufkey: BIO
    pkey: EVP_PKEY
    mdctx: EVP_MD_CTX
    pkeyCtx: EVP_PKEY_CTX
    key = key   # make a copy of key to be extra safe
    data = data # make a copy of data to be extra safe

  defer:
    if not mdctx.isNil: EVP_MD_CTX_destroy(mdctx)
    if not pkeyCtx.isNil: EVP_PKEY_CTX_free(pkeyCtx)
    if not pkey.isNil: EVP_PKEY_free(pkey)
    if defined(windows):
      #TODO: for some reason this segfaults on windows, so we are going to leak memory instead.
      # if not bufkey.isNil:
      #   discard BIO_set_close(bufkey, BIO_NOCLOSE)
      #   discard BIO_free(bufkey)
      discard
    else:
      if not bufkey.isNil: discard BIO_free(bufkey)

  # Create a buffer for our work
  bufkey = BIO_new_mem_buf(key[0].addr, key.len.cint)
  if bufkey.isNil:
    raise newException(Exception, "Out of memory")

  # Create and read the private key
  pkey = PEM_read_bio_PrivateKey(bufkey, nil, nil, nil)
  if pkey.isNil:
    raise newException(Exception, "Invalid PrivateKey")

  # Initialize PEM Key Context
  pkeyCtx = EVP_PKEY_CTX_new(pkey, nil)
  if EVP_PKEY_sign_init(pkeyCtx) <= 0:
    raise newException(Exception, "Invalid value")

  # create MD
  mdCtx = EVP_MD_CTX_create()
  if mdctx.isNil:
    raise newException(Exception, "Out of memory")

  # Initialize the DigestSign operation using alg
  if EVP_DigestSignInit(mdCtx, nil, alg, nil, pkey) != 1:
    raise newException(Exception, "Invalid value")

  # Call update with the message
  if EVP_DigestUpdate(mdCtx, data[0].addr, data.len.cuint) != 1:
    raise newException(Exception, "Invalid value")

  # First, call EVP_DigestSignFinal with a NULL sig parameter to get length
  # of sig. Length is returned in slen
  var sLen: csize_t
  if EVP_DigestSignFinal(mdCtx, nil, addr sLen) != 1:
    raise newException(Exception, "Invalid value")
  # Allocate memory for signature based on returned size
  result = newString(sLen)
  # Get the signature
  if EVP_DigestSignFinal(mdCtx, addr result[0], addr sLen) != 1:
    raise newException(Exception, "Invalid value")
