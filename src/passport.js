const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const GitHubStrategy = require('passport-github2').Strategy;
const config = require('./config');
const User = require('./models/User');

const enabled = new Set();

// Finds or creates a local user for an OAuth profile ("secure profile sync").
async function syncOAuthUser(idField, profile) {
  const emailObj = (profile.emails && profile.emails[0]) || null;
  const email = emailObj && emailObj.value ? emailObj.value.toLowerCase() : null;
  const verified = emailObj ? emailObj.verified === true || emailObj.verified === 'true' : false;
  const avatar = profile.photos && profile.photos[0] && profile.photos[0].value;
  const name = profile.displayName || profile.username || (email ? email.split('@')[0] : 'User');

  let user = await User.findOne({ [idField]: profile.id });
  if (!user && email) {
    const existing = await User.findOne({ email });
    if (existing) {
      // Only link to an existing account if the provider verified the email (prevents account takeover)
      if (!verified) throw new Error('OAuth email is not verified; cannot link to existing account');
      user = existing;
    }
  }
  if (!user) {
    user = new User({
      name,
      email: email || `${profile.provider}-${profile.id}@users.noreply.local`,
      role: 'Employee', // new social users always start with the lowest privilege
    });
  }
  user[idField] = profile.id;
  if (avatar) user.avatar = avatar;
  if (!user.name) user.name = name;
  await user.save();
  return user;
}

function use(name, Strategy, creds, idField, extra = {}) {
  if (!creds.clientID || !creds.clientSecret) return;
  passport.use(
    new Strategy(
      { ...creds, callbackURL: `${config.baseUrl}/api/v1/auth/${name}/callback`, ...extra },
      async (accessToken, refreshToken, profile, done) => {
        try {
          done(null, await syncOAuthUser(idField, profile));
        } catch (err) {
          done(err);
        }
      }
    )
  );
  enabled.add(name);
}

use('google', GoogleStrategy, config.google, 'googleId');
use('github', GitHubStrategy, config.github, 'githubId', { scope: ['user:email'] });

module.exports = { passport, enabled };
