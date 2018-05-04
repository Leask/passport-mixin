/**
 * Module dependencies.
 */
var url = require('url')
  , util = require('util')
  , request = require('request')
  , OAuth2Strategy = require('passport-oauth2')
  , utils = require('./utils')
  , Profile = require('./profile')
  , InternalOAuthError = require('passport-oauth2').InternalOAuthError;

/**
 * `Strategy` constructor.
 *
 * The Mixin authentication strategy authenticates requests by delegating to
 * Mixin using the OAuth 2.0 protocol.
 *
 * Applications must supply a `verify` callback which accepts an `accessToken`,
 * `refreshToken` and service-specific `profile`, and then calls the `done`
 * callback supplying a `user`, which should be set to `false` if the
 * credentials are not valid.  If an exception occured, `err` should be set.
 *
 * Options:
 *   - `clientID`      your Mixin application's Client ID
 *   - `clientSecret`  your Mixin application's Client Secret
 *   - `callbackURL`   URL to which Mixin will redirect the user after granting authorization
 *   - `scope`         array of permission scopes to request. Valid scopes include:
 *                     'user', 'public_repo', 'repo', 'gist', or none.
 *                     (see http://developer.Mixin.com/v3/oauth/#scopes for more info)
 *   — `userAgent`     All API requests MUST include a valid User Agent string.
 *                     e.g: domain name of your application.
 *
 * Examples:
 *
 *     passport.use(new MixinStrategy({
 *         clientID: '123-456-789',
 *         clientSecret: 'shhh-its-a-secret',
 *         callbackURL: 'https://www.example.net/auth/mixin/callback',
 *         userAgent: 'myapp.com'
 *       },
 *       function(accessToken, refreshToken, profile, done) {
 *         User.findOrCreate(..., function (err, user) {
 *           done(err, user);
 *         });
 *       }
 *     ));
 *
 * @param {Object} options
 * @param {Function} verify
 * @api public
 */
function Strategy(options, verify) {
  options = options || {};
  options.authorizationURL = options.authorizationURL || 'https://mixin.one/oauth/authorize';
  options.tokenURL = options.tokenURL || 'https://api.mixin.one/oauth/token';
  options.scopeSeparator = options.scopeSeparator || ',';
  options.customHeaders = options.customHeaders || {};
  if (!options.customHeaders['User-Agent']) {
    options.customHeaders['User-Agent'] = options.userAgent || 'passport-mixin';
  }
  OAuth2Strategy.call(this, options, verify);
  this.name = 'mixin';
  this._tokenURL       = options.tokenURL;
  this._userProfileURL = options.userProfileURL || 'https://api.mixin.one/me';
  this._oauth2.useAuthorizationHeaderforGET(false);
  this._oauth2.setAccessTokenName('accesstoken');
}

/**
 * Inherit from `OAuth2Strategy`.
 */
util.inherits(Strategy, OAuth2Strategy);

/**
 * Retrieve user profile from Mixin.
 *
 * This function constructs a normalized profile, with the following properties:
 *
 *   - `provider`         always set to `Mixin`
 *   - `id`               the user's Mixin ID
 *   - `username`         the user's Mixin username
 *   - `displayName`      the user's full name
 *   - `profileUrl`       the URL of the profile for the user on Mixin
 *   - `emails`           the user's email addresses
 *
 * @param {String} accessToken
 * @param {Function} done
 * @api protected
 */
Strategy.prototype.userProfile = function(accessToken, done) {
  request({
    url     : this._userProfileURL,
    method  : 'GET',
    json    : true,
    headers : {
      'Authorization' : `Bearer ${accessToken}`,
    }
  }, (err, response, body) => {
    // Mixin Debug {
        // console.log('[Passport DEBUG] request: ', this._userProfileURL, accessToken);
        // console.log('[Passport DEBUG] body: ', body);
    // }
    if (err || !body || (body && body.error)) {
      return done(new InternalOAuthError('Failed to fetch user profile', err));
    }
    var profile = Profile.parse(body.data);
    profile.provider  = 'mixin';
    profile._raw = body;
    profile._json = body.data;
    done(null, profile);
  });
};

let getOAuthAccessToken = (url, code, params, callback) => {
  var params= params || {};
  var codeParam = (params.grant_type === 'refresh_token') ? 'refresh_token' : 'code';
  params[codeParam] = code;
  request.post({url : url, body : params, json : true}, (error, response, results) => {
    if( error ) callback(error);
    else {
      results           = results && results.data;
      var access_token  = results && results.access_token;
      var refresh_token = results && results.refresh_token;
      if (results) {
        delete results.refresh_token;
      }
      callback(null, access_token, refresh_token, results); // callback results =-=
    }
  });
};

/**
 * Authenticate request by delegating to a service provider using OAuth 2.0.
 *
 * @param {Object} req
 * @api protected
 */
Strategy.prototype.authenticate = function(req, options) {
  options = options || {};
  var self = this;
  if (req.query && req.query.error) {
    if (req.query.error == 'access_denied') {
      return this.fail({ message: req.query.error_description });
    } else {
      return this.error(new AuthorizationError(req.query.error_description, req.query.error, req.query.error_uri));
    }
  }
  var callbackURL = options.callbackURL || this._callbackURL;
  if (callbackURL) {
    var parsed = url.parse(callbackURL);
    if (!parsed.protocol) {
      // The callback URL is relative, resolve a fully qualified URL from the
      // URL of the originating request.
      callbackURL = url.resolve(utils.originalURL(req, { proxy: this._trustProxy }), callbackURL);
    }
  }
  var meta = {
    authorizationURL: this._oauth2._authorizeUrl,
    tokenURL: this._oauth2._accessTokenUrl,
    clientID: this._oauth2._clientId
  }
  if (req.query && req.query.code) {
    function loaded(err, ok, state) {
      if (err) { return self.error(err); }
      if (!ok) {
        return self.fail(state, 403);
      }
      var code = req.query.code;
      var params = self.tokenParams(options);
      params.grant_type = 'authorization_code';
      params.client_id  = self._oauth2._clientId;
      params.client_secret = self._oauth2._clientSecret;
      if (callbackURL) { params.redirect_uri = callbackURL; }
      getOAuthAccessToken(self._tokenURL, code, params,
        (err, accessToken, refreshToken, params) => {
          // Mixin Debug {
              // console.log('[Passport DEBUG] auth: ', err, accessToken, refreshToken, params);
          // }
        if (err) { return self.error(self._createOAuthError('Failed to obtain access token', err)); }
          self._loadUserProfile(accessToken, function(err, profile) {
            if (err) { return self.error(err); }
            function verified(err, user, info) {
              if (err) { return self.error(err); }
              if (!user) { return self.fail(info); }

              info = info || {};
              if (state) { info.state = state; }
              self.success(user, info);
            }
            try {
              if (self._passReqToCallback) {
                var arity = self._verify.length;
                if (arity == 6) {
                  self._verify(req, accessToken, refreshToken, params, profile, verified);
                } else { // arity == 5
                  self._verify(req, accessToken, refreshToken, profile, verified);
                }
              } else {
                var arity = self._verify.length;
                if (arity == 5) {
                  self._verify(accessToken, refreshToken, params, profile, verified);
                } else { // arity == 4
                  self._verify(accessToken, refreshToken, profile, verified);
                }
              }
            } catch (ex) {
              return self.error(ex);
            }
          });
        }
      );
    }
    var state = req.query.state;
    try {
      var arity = this._stateStore.verify.length;
      if (arity == 4) {
        this._stateStore.verify(req, state, meta, loaded);
      } else { // arity == 3
        this._stateStore.verify(req, state, loaded);
      }
    } catch (ex) {
      return this.error(ex);
    }
  } else {
    var params = this.authorizationParams(options);
    params.response_type = 'code';
    if (callbackURL) { params.redirect_uri = callbackURL; }
    var scope = options.scope || this._scope;
    if (scope) {
      if (Array.isArray(scope)) { scope = scope.join(this._scopeSeparator); }
      params.scope = scope;
    }
    var state = options.state;
    if (state) {
      params.state = state;
      var parsed = url.parse(this._oauth2._authorizeUrl, true);
      utils.merge(parsed.query, params);
      parsed.query['client_id'] = this._oauth2._clientId;
      delete parsed.search;
      var location = url.format(parsed);
      this.redirect(location);
    } else {
      function stored(err, state) {
        if (err) { return self.error(err); }
        if (state) { params.state = state; }
        var parsed = url.parse(self._oauth2._authorizeUrl, true);
        utils.merge(parsed.query, params);
        parsed.query['client_id'] = self._oauth2._clientId;
        delete parsed.search;
        var location = url.format(parsed);
        self.redirect(location);
      }
      try {
        var arity = this._stateStore.store.length;
        if (arity == 3) {
          this._stateStore.store(req, meta, stored);
        } else { // arity == 2
          this._stateStore.store(req, stored);
        }
      } catch (ex) {
        return this.error(ex);
      }
    }
  }
};

/**
 * Expose `Strategy`.
 */
module.exports = Strategy;
