var GoogleStrategy = require('passport-google-openidconnect').Strategy,
    CourseraOAuthStrategy = require('./passport-coursera-oauth').Strategy,
    TwitterStrategy = require('passport-twitter').Strategy,
    LocalStrategy = require('passport-local').Strategy,
    LtiStrategy = require('./passport-lti').Strategy,
    OAuth2Strategy = require('passport-oauth2').Strategy,
    async = require('async'),
    mdb = require('./mdb'),
    GithubApi = require('github'),
    validator = require('validator'),
    _ = require('underscore');

module.exports.githubStrategy = function (rootUrl) {
    return new OAuth2Strategy({
        authorizationURL: 'https://github.com/login/oauth/authorize',
        tokenURL: 'https://github.com/login/oauth/access_token',
        clientID: process.env.GITHUB_CLIENT_ID,
        clientSecret: process.env.GITHUB_CLIENT_SECRET,
        scope: 'user,repo', // https://developer.github.com/v3/oauth/#scopes
        callbackURL: rootUrl + '/auth/github/callback',
        passReqToCallback: true
    }, function (req, accessToken, refreshToken, profile, done) {
        // Load the github user id
        var github = new GithubApi({ version: '3.0.0' });

        github.authenticate({
            type: 'oauth',
            token: accessToken
        });

        github.users.get({}, function (err, user) {
            addUserAccount(req, 'githubId', user.id, user.name, '', null, function () {
                // Save the github access token
                req.user.githubAccessToken = accessToken;
                req.user.save(done);
            });
        });
    });
};

module.exports.courseraStrategy = function (rootUrl) {
    return new CourseraOAuthStrategy({
        requestTokenURL: 'https://authentication.coursera.org/auth/oauth/api/request_token',
        accessTokenURL: 'https://authentication.coursera.org/auth/oauth/api/access_token',
        consumerKey: process.env.COURSERA_CONSUMER_KEY,
        consumerSecret: process.env.COURSERA_CONSUMER_SECRET,
        callbackURL: rootUrl + '/auth/coursera/callback',
        passReqToCallback: true
    }, function (req, token, tokenSecret, profile, done) {
        console.log('coursera profile = ', profile);
        addUserAccount(req, 'courseraOAuthId', profile.id, profile.full_name, null, null, done);
    });
};

module.exports.googleStrategy = function (rootUrl) {
    return new GoogleStrategy({
        callbackURL: rootUrl + '/auth/google/callback',
        clientID: process.env.GOOGLE_CLIENT_ID,
        clientSecret: process.env.GOOGLE_CLIENT_SECRET,
        scope: 'email',
        passReqToCallback: true
    }, function (req, iss, sub, profile, accessToken, refreshToken, done) {
        addUserAccount(req, 'googleOpenId', profile.id, profile.displayName, profile._json.email, null, done);
    });
};

module.exports.twitterStrategy = function (rootUrl) {
    return new TwitterStrategy({
        consumerKey: process.env.TWITTER_CONSUMER_KEY,
        consumerSecret: process.env.TWITTER_CONSUMER_SECRET,
        callbackURL: rootUrl + '/auth/twitter/callback',
        passReqToCallback: true
    }, function (req, token, tokenSecret, profile, done) {
        addUserAccount(req, 'twitterOAuthId', profile.id_str, profile.name, null, null, done);
    });
};

module.exports.localStrategy = function (rootUrl) {
    return new LocalStrategy({
        passReqToCallback: true
    }, function (req, username, password, done) {
        mdb.User.findOne({ username: username }, function (err, user) {
            if (err) {
                return done(err);
            }

            if (!user) {
                return done(null, false);
            }

            // BADBAD: password should be hashed
            if (user.password != password) {
                return done(null, false);
            }

            req.user = user;

            return done(null, user);
        });
    });
};

module.exports.ltiStrategy = function (rootUrl) {
    return new LtiStrategy({
        returnURL: '/just-logged-in',
        consumerKey: process.env.LTI_KEY,
        consumerSecret: process.env.LTI_SECRET
    }, function (req, identifier, profile, done) {
        var displayName = 'Remote User',
            email = profile.lis_person_contact_email_primary || '';

        if (!_.isEmpty(profile.lis_person_name_full) && profile.lis_person_name_full != email) {
            displayName = profile.lis_person_name_full;
        }

        var course = profile.custom_ximera; // custom parameter from Canvas

        addUserAccount(req, 'ltiId', identifier, displayName, email, course, done);
    });
};

// Redirect anonymous users to login page
module.exports.authMiddleware = function (req, res, next) {
    var anonymousPaths = [
        '/login',
        '/auth/google',
        '/auth/google/callback',
        '/auth/github',
        '/auth/github/callback',
        '/lti'
    ];

    var allowAnonymous = ('/' == req.originalUrl) || _.some(anonymousPaths, function (url) {
        return req.originalUrl.startsWith(url);
    });

    if (!(req.user || allowAnonymous)) {
        res.redirect('/login');

        return;
    }

    next();
};

module.exports.addUserInfoMiddleware = function (req, res, next) {
    res.locals.user = req.user;
    next();
};

module.exports.login = function (req, res) {
    if (!req.user) {
        res.render('login');

        return;
    }

    res.redirect('/just-logged-in');
};

function updateUser(user, authField, authId, name, email, course) {
    user[authField] = authId;

    if (_.isEmpty(user.name)) {
        user.name = name;
    }

    if (_.isEmpty(user.email)) {
        user.email = email;
    }

    if (!_.isEmpty(course)) {
        user.course = course;
    }
}

function addUserAccount(req, authField, authId, name, email, course, done) {
    var searchFields = {};

    searchFields[authField] = authId;

    email = validator.normalizeEmail(email, {
        lowercase: true,
        remove_dots: false,
        remove_extension: false
    });

    if (!req.user) { // New user
        mdb.User.findOne(searchFields, function (err, user) {
            if (err) {
                done(err, null);

                return;
            }

            if (!user) {
                req.user = new mdb.User({
                    name: name,
                    email: email,
                    course: course
                });

                req.user[authField] = authId;

                req.user.save(function (err) {
                    done(err, req.user);
                });
            } else {
                req.user = user;

                updateUser(req.user, authField, authId, name, email, course);

                req.user.save(function (err) {
                    done(err, req.user);
                });
            }
        });
    } else { // Add account to existing user; remove account from other users.
        if (req.user[authField] == authId) { // If user already has account, we're done.
            updateUser(req.user, authField, authId, name, email, course);

            req.user.save(function (err) {
                done(err, req.user);
            });
        } else {
            mdb.User.find(searchFields, function (err, users) {
                async.eachSeries(users, function (user, callback) {
                    user[authField] = undefined;
                    user.save(callback);
                }, function (err) {
                    if (err) {
                        done(err, null);
                    } else {
                        updateUser(req.user, authField, authId, name, email, course);

                        req.user.save(function (err) {
                            done(err, req.user);
                        });
                    }
                });
            });
        }
    }
}
