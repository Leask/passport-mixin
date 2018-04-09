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

  if (!json || json.userinfo) {
    return profile;
  }

  profile.id = String(json.userinfo.id);
  profile.displayName = json.userinfo.nickname;
  profile.username = json.userinfo.nickname;
  profile.profileUrl = `https://openapi.iveryone.wuyan.cn/PersonalHome/${json.userinfo.id}`;
  if (json.userinfo.email) {
    profile.emails = [{ value: json.userinfo.email }];
  }
  if (json.userinfo.avatar) {
    profile.photos = [{ value: json.userinfo.avatar }];
  }
  return profile;
};
