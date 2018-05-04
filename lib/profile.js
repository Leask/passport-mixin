/**
 * Parse profile.
 *
 * @param {Object|String} json
 * @return {Object}
 * @api private
 */
exports.parse = function(json) {
  if ('string' == typeof json) {
    json = JSON.parse(json);
  }

  var profile = {};

  if (!json) {
    return profile;
  }

  // json = {
  //   type                   : 'user',
  //   user_id                : '36029b33-838f-4dbe-ae9b-f0e86226d53d',
  //   identity_number        : '1092619',
  //   full_name              : 'Leask',
  //   avatar_url             : '',
  //   relationship           : 'ME',
  //   mute_until             : '0001-01-01T00:00:00Z',
  //   created_at             : '2018-03-26T06:55:00.967014194Z',
  //   is_verified            : false,
  //   session_id             : 'fbeec3c1-004d-4662-bd3c-205faf655a2e',
  //   phone                  : '',
  //   pin_token              : '',
  //   invitation_code        : '',
  //   code_id                : 'dab27486-6773-491f-99c8-261b6ea66f8f',
  //   code_url               : 'https://mixin.one/codes/dab27486-6773-491f-99c8-261b6ea66f8f',
  //   has_pin                : true,
  //   receive_message_source : 'EVERYBODY',
  // };

  profile.id          = json.user_id;
  profile.displayName = json.full_name;
  profile.username    = json.identity_number;
  profile.profileUrl  = json.code_url;
  if (json.avatar_url) {
    profile.photos = [{value : json.avatar_url}];
  }
  return profile;
};
