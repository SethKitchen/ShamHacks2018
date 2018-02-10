'use strict';
var express = require('express');
var app = express();
var http = require('http');
var https = require('https');
var fs = require('fs');
var moment = require('moment');
var passport = require('passport');
var util = require('util');
var bodyParser = require('body-parser');
var cookieParser = require('cookie-parser');
var session = require('express-session');
var GoogleStrategy = require('passport-google-oauth2').Strategy;
var path = require('path');
var favicon = require('serve-favicon');
var logger = require('morgan');
var sql = require('tedious').Connection;
var Request = require('tedious').Request;
var ConnectionPool = require('tedious-connection-pool');
var TYPES = require('tedious').TYPES;
var forceSsl = require('express-force-ssl');
var math = require('mathjs');
var GOOGLE_CLIENT_ID = "854713659820-vobut1a24pavldh4bv3jgiecbm21dqh2.apps.googleusercontent.com";
var GOOGLE_CLIENT_SECRET = "QUjKNxc_2qKXp1SaDpmEhaV3";
var MemoryStore = session.MemoryStore;
var sessionStore = new MemoryStore();

process.on('uncaughtException', function (err) {
    console.error(err);
    console.log("Node NOT Exiting...");
});

var options = {
    key: fs.readFileSync('server.key'),
    cert: fs.readFileSync('server.crt')
};

var dbConfig = {
    server: "shamhacks.database.windows.net",
    userName: 'sjkyv5',
    password: 'hacker1!',
    // When you connect to Azure SQL Database, you need these next options.  
    options: { encrypt: true, database: 'ShamHacks2018', rowCollectionOnDone: true }
};

var poolConfig = {
    min: 2,
    max: 4,
    log: true
};

//create the pool
var pool = new ConnectionPool(poolConfig, dbConfig);

pool.on('error', function (err) {
    console.error(err);
});

app.set('trust proxy', 1);
app.use(forceSsl);

// Passport session setup.
//   To support persistent login sessions, Passport needs to be able to
//   serialize users into and deserialize users out of the session.  Typically,
//   this will be as simple as storing the user ID when serializing, and finding
//   the user by ID when deserializing.  However, since this example does not
//   have a database of user records, the complete Google profile is
//   serialized and deserialized.
passport.serializeUser(function (user, done) {
    done(null, user);
});

passport.deserializeUser(function (obj, done) {
    done(null, obj);
});


// Use the GoogleStrategy within Passport.
//   Strategies in Passport require a `verify` function, which accept
//   credentials (in this case, an accessToken, refreshToken, and Google
//   profile), and invoke a callback with a user object.
passport.use(new GoogleStrategy({
    clientID: GOOGLE_CLIENT_ID,
    clientSecret: GOOGLE_CLIENT_SECRET,
    //NOTE :
    //Carefull ! and avoid usage of Private IP, otherwise you will get the device_id device_name issue for Private IP during authentication
    //The workaround is to set up thru the google cloud console a fully qualified domain name such as http://mydomain:3000/ 
    //then edit your /etc/hosts local file to point on your private IP. 
    //Also both sign-in button + callbackURL has to be share the same url, otherwise two cookies will be created and lead to lost your session
    //if you use it.
    callbackURL: "https://virtuschools.com/signin-google",
    passReqToCallback: true
},
    function (request, accessToken, refreshToken, profile, done) {
        // asynchronous verification, for effect...
        process.nextTick(function () {

            // To keep the example simple, the user's Google profile is returned to
            // represent the logged-in user.  In a typical application, you would want
            // to associate the Google account with a user record in your database,
            // and return that user instead.
            var picture = null;
            if (profile.photos.length > 0) {
                picture = profile.photos[0].value;
            }
            InsertOrUpdateUserInDatabase(profile.id, profile.name.familyName, profile.name.givenName, profile.email, picture, request.session.id, function () {

                return done(null, profile);
            });
        });
    }
));

function sessionCleanup() {
    sessionStore.all(function (err, sessions) {
        for (var i = 0; i < sessions.length; i++) {
            sessionStore.get(sessions[i], function () { });
        }
    });
}

setInterval(sessionCleanup, 1.728 * Math.pow(10 ^ 8));

// view engine setup
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');

// uncomment after placing your favicon in /public
app.use(favicon(__dirname + '/public/logo2.ico'));
app.use(logger('dev'));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));
app.use(session({
    secret: 'i like socks',
    cookie: { secure: true },
    store: sessionStore,
    proxy: true,
    resave: false,
    saveUninitialized: true
}));
app.use(passport.initialize());
app.use(passport.session());

/*
app.use('/', routes);
app.use('/users', users);
*/

// GET /auth/google
//   Use passport.authenticate() as route middleware to authenticate the
//   request.  The first step in Google authentication will involve
//   redirecting the user to google.com.  After authorization, Google
//   will redirect the user back to this application at /auth/google/callback
app.get('/auth/google', passport.authenticate('google', {
    scope: [
        'https://www.googleapis.com/auth/plus.login',
        'https://www.googleapis.com/auth/plus.profile.emails.read']
}));

// GET /auth/google/callback
//   Use passport.authenticate() as route middleware to authenticate the
//   request.  If authentication fails, the user will be redirected back to the
//   login page.  Otherwise, the primary route function function will be called,
//   which, in this example, will redirect the user to the home page.
app.get('/signin-google',
    passport.authenticate('google', {
        successRedirect: '/',
        failureRedirect: '/login'
    }));

app.get('/logout', function (req, res) {
    req.logout();
    res.redirect('/');
});

app.get('/', function (req, res) {
    res.render('index', { title: 'ShamHacks', user: req.user });
});

app.get('/account', ensureAuthenticated, function (req, res) {
    //Example of courses being sent: var courses = [{ name: "A" }];
    console.log(req.user.id);

    GetCourses(req.user.id, function (courses) {
        res.render('account', { user: req.user, courses: courses, message: undefined });
    });
});

app.get('/login', function (req, res) {
    res.render('Login', { user: req.user });
});

app.get('/education', function (req, res) {
    res.render('education', { user: req.user });
});

app.get('/contact', function (req, res) {
    res.render('contact', { user: req.user });
});



function isNumeric(n) {
    return !isNaN(parseFloat(n)) && isFinite(n);
}



String.prototype.replaceAll = function (search, replacement) {
    var target = this;
    return target.replace(new RegExp(search, 'g'), replacement);
};



function getDateTime() {

    var date = new Date();

    var hour = date.getHours();
    hour = (hour < 10 ? "0" : "") + hour;

    var min = date.getMinutes();
    min = (min < 10 ? "0" : "") + min;

    var sec = date.getSeconds();
    sec = (sec < 10 ? "0" : "") + sec;

    var year = date.getFullYear();

    var month = date.getMonth() + 1;
    month = (month < 10 ? "0" : "") + month;

    var day = date.getDate();
    day = (day < 10 ? "0" : "") + day;

    return year + ":" + month + ":" + day + ":" + hour + ":" + min + ":" + sec;

}




// catch 404 and forward to error handler
app.use(function (req, res, next) {
    var err = new Error('Not Found');
    err.status = 404;
    next(err);
});





// error handlers

// development error handler
// will print stacktrace
if (app.get('env') === 'development') {
    app.use(function (err, req, res, next) {
        res.status(err.status || 500);
        res.render('error', {
            message: err.message,
            error: err
        });
    });
}

// production error handler
// no stacktraces leaked to user
app.use(function (err, req, res, next) {
    res.status(err.status || 500);
    res.render('error', {
        message: err.message,
        error: {}
    });
});




// Simple route middleware to ensure user is authenticated.
//   Use this route middleware on any resource that needs to be protected.  If
//   the request is authenticated (typically via a persistent login session),
//   the request will proceed.  Otherwise, the user will be redirected to the
//   login page.
function ensureAuthenticated(req, res, next) {
    if (req.user) { return next(); }
    res.redirect('/login');
}


module.exports = app;
https.createServer(options, app).listen(443);
http.createServer(app).listen(process.env.PORT || 80);