'use strict'

const crypto = require('crypto')
const https = require('https')
const qs = require('querystring')
const modhex = require('./modhex.js')

// List of valid servers. We go through them in round-robin fashion.
var servers = ['api.yubico.com', 'api2.yubico.com', 'api3.yubico.com', 'api4.yubico.com', 'api5.yubico.com']
var currentServerIdx = Math.floor(Math.random() * servers.length)

var DEFAULT_NONCE_LENGTH = 40 // Length of random nonce generated per-request
var DEFAULT_MAX_TRIES = 3 // For automatic retry

function Yub (clientID, secretKey, options) {
  // store the client credentials
  // Apply here https://upgrade.yubico.com/getapikey/
  if (!clientID || !secretKey) throw new Error('Provide a client ID & secret key to yub.init()!')
  if (!options) options = {}

  this.clientID = clientID
  this.secretKey = secretKey
  this.maxTries = options.maxTries || DEFAULT_MAX_TRIES
  this.nonceLength = options.nonceLength || DEFAULT_NONCE_LENGTH
}

// parse the returned date which is CR/LF delimited string with key/value pairs
// separated by '='
function parse (data) {
  var obj = data.split('\r\n')
  var retval = {}
  var kv = []

  Object.keys(obj).map(function (key) {
    kv = obj[key].split('=', 2)
    if (kv[0].length > 0) { retval[kv[0]] = kv[1] }
  })
  return retval
}

// extract the identity portion of the Yubikey OTP i.e.
// the string with last 32 characters removed
function calculateIdentity (otp) { return (otp.length > 32) ? otp.substring(0, otp.length - 32) : null }
// extract the encrypted portion of the Yubikey OTP i.e.
// the last 32 characters
function calculateEncrypted (otp) { return (otp.length > 32) ? otp.substring(otp.length - 32, otp.length) : null }
// calculate the string that is required to be hashed i.e.
//  keys in alphabetical order, separated from values by '='
//  and by each other by '&' (like querystrings, but without the escaping)
function calculateStringToHash (obj) { return Object.keys(obj).sort().map(function (key) { return key + '=' + obj[key] }).join('&') }
// calculate the Hmac signature of an object
// according to instructions here: https://code.google.com/p/yubikey-val-server-php/wiki/ValidationProtocolV20
function calculateHmac (obj, secretKey) {
  const str = calculateStringToHash(obj)
  const buf = Buffer.from(secretKey, 'base64')
  const hmac = crypto.createHmac('sha1', buf)
  return hmac.update(str).digest('base64')
}

// Verify with a random Yubico server.
Yub.prototype.verifyWithYubico = function (params, callback, currentTry) {
  // Automatic retry logic
  if (!currentTry) currentTry = 1
  // Choose a server in round-robin fashion. First offset is random.
  currentServerIdx = (currentServerIdx + 1) % servers.length
  const server = servers[currentServerIdx]
  const uri = 'https://' + server + '/wsapi/2.0/verify'
  const fullURI = uri + '?' + qs.stringify(params)
  const me = this

  // Send to Yubico.
  https.get(fullURI, function (res) {
    // Error handling
    var shouldRetry = (currentTry < me.maxTries)
    var badStatus = (res && res.statusCode !== 200)
    var serverError = (res && res.statusCode >= 500)
    if (shouldRetry && serverError) {
      // Errored, but retry
      return me.verifyWithYubico(params, callback, currentTry + 1)
    } else if (badStatus) {
      return callback(new Error('Bad status code: ' + res.statusCode))
    }
    // Parse body & go
    var buffer = ''
    res.on('data', function (chunk) { buffer += chunk })
    res.on('end', function () {
      var body = parse(buffer)
      // check whether the signature of the reply checks out
      var bodyh = body.h
      delete body.h
      var h = calculateHmac(body, me.secretKey)
      body.signatureVerified = (bodyh === h.replace('=', ''))
      // check whether the nonce is the same as the one we gave it
      body.nonceVerified = (params.nonce === body.nonce)
      // calculate the key's identity
      body.identity = null
      body.encrypted = null
      body.encryptedHex = null
      body.serial = null
      if (body.status === 'OK') {
        body.identity = calculateIdentity(params.otp)
        body.encrypted = calculateEncrypted(params.otp)
        body.encryptedHex = modhex.decode(body.encrypted)
        body.serial = modhex.decodeInt(body.identity)
        body.valid = (body.signatureVerified && body.nonceVerified)
      } else {
        body.valid = false
      }
      callback(null, body)
    })
  })
    .on('error', callback)
}

// Calculate the params to be sent to Yubico.
Yub.prototype.calculateParams = function (otp, callback) {
  var me = this
  // create a nonceLength-character random string
  crypto.randomBytes(me.nonceLength / 2, function (err, buf) {
    if (err) return callback(err)
    // turn it to hex
    var nonce = buf.toString('hex')
    // create parameters to send to web service
    var params = { id: me.clientID, nonce: nonce, otp: otp }
    // calculate sha1 signature
    params.h = calculateHmac(params, me.secretKey)
    callback(null, params)
  })
}

// Verify that the supplied one-time-password is valid or not
// calls back with (err,data). If err is not null, then you have
// an object in data to work with.
Yub.prototype.verify = function (otp, callback) {
  var me = this
  this.calculateParams(otp, function (err, params) {
    if (err) return callback(err)
    me.verifyWithYubico(params, callback)
  })
}

// If we have no network connectivity, we still may wish to extract the
// identity from the OTP, but handy for offline applications.
Yub.prototype.verifyOffline = function (otp, callback) {
  var identity = calculateIdentity(otp)
  var encrypted = calculateEncrypted(otp)
  var body = {
    t: null,
    otp: otp,
    nonce: null,
    sl: '0',
    status: null,
    signatureVerified: false,
    nonceVerified: false,
    identity: identity,
    encrypted: encrypted,
    encryptedHex: modhex.decode(encrypted),
    serial: modhex.decodeInt(identity),
    valid: false
  }
  callback(null, body)
}

// Export Yub. To maintain backcompat, we attach a few static properties.
module.exports = Yub

var legacyInstance = null
// Don't break old methods!
Yub.init = function (clientID, secretKey) {
  // As not to break backcompat, don't use retries with old API
  legacyInstance = new Yub(clientID, secretKey, { maxTries: 0 })
}

Yub.verify = function (otp, callback) {
  if (!legacyInstance) throw new Error('init() before verifying!')
  return legacyInstance.verify(otp, callback)
}

Yub.verifyOffline = Yub.prototype.verifyOffline // No actual legacy instance required
Yub._calculateHmac = calculateHmac // for tests
Yub._calculateStringToHash = calculateStringToHash // for tests
Yub._servers = servers // for tests
