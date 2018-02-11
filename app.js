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
var GOOGLE_CLIENT_ID = "116276954926-003dqd6d3aa4tomb92lje1ji96qt9eic.apps.googleusercontent.com";
var GOOGLE_CLIENT_SECRET = "IH3z7tFCs3PbdaTjsiU8TrPP";
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
    callbackURL: "https://localhost/signin-google",
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

app.get('/sell', function (req, res) {
    res.render('sellAnItem', { title: 'ShamHacks', user: req.user });
});

app.get('/', function (req, res) {
    res.render('index', { title: 'ShamHacks', user: req.user });
});

app.get('/viewSelling', function (req, res) {
    try {
        GetProducts(req.user.id, function (err, items) {
            console.log(items);
            res.render('manageItems', { title: 'ShamHacks', user: req.user, items: items });
        });
    }
    catch (ex) {
        console.log(ex);
    }
});

app.post('/updateSelling', function (req, res) {
    try {
        var title = req.body.itemname;
        var cost = req.body.itemcost;
        var quantityAvailable = req.body.itemquantity;
        var pickUp = req.body.itempickup;
        var mainimage = req.body.itemimage;
        var image2 = req.body.itemimage2;
        var image3 = req.body.itemimage3;
        var image4 = req.body.itemimage4;
        var image5 = req.body.itemimage5;
        var id = req.body.itemid;
        var tags = req.body.itemtags;
        var deleteIt = req.body.deleteItem;
        if (deleteIt.toLowerCase() == "yes" || deleteIt.toLowerCase() == "y") {
            DeleteProduct(req.user.id, id, function (err) {
                res.redirect('/viewSelling');
            });
        }
        else {
            UpdateProducts(req.user.id, title, cost, quantityAvailable, pickUp, mainimage, image2, image3, image4, image5, id, tags, function (err) {
                res.redirect('/viewSelling');
            });
        }
    }
    catch (ex) {
        console.log(ex);
    }
});

app.get('/account', ensureAuthenticated, function (req, res) {
    console.log(req.user.id);
    GetCurrentProfileInformation(req.user, function (err, data) {
        res.render('account', { user: req.user, data: data, message: undefined });
    });
});

app.get('/login', function (req, res) {
    res.render('Login', { user: req.user });
});

app.get('/contact', function (req, res) {
    res.render('contact', { user: req.user });
});

app.post('/PostNewItem', ensureAuthenticated, function (req, res) {
    var title = req.body.newitemname;
    var cost = req.body.newitemcost;
    var quantityAvailable = req.body.newitemquantity;
    var pickUp = req.body.newitempickup;
    var image = req.body.newitemimage;
    PostNewItem(req.user.id, title, cost, quantityAvailable, pickUp, image, function (err) {
        res.redirect('/account');
    });
});

app.post('/UpdateProfileInfo', ensureAuthenticated, function (req, res) {
    var dob = req.body.newdob;
    var addr = req.body.newaddr;
    var city = req.body.newcity;
    var state = req.body.newstate;
    var zip = req.body.newzipcode;
    var company = req.body.newcompany;
    var phoneNumber = req.body.newphonenumber;
    var gender = req.body.newgender;
    var race = req.body.newrace;
    var isVet = req.body.newvet;
    var branch = req.body.newmilitarybranch;
    var war = req.body.newwar;
    var rank = req.body.newrank;
    var troops = req.body.newtroopdescript;
    var job = req.body.newjob;
    var video = req.body.newvideo;
    UpdateProfile(req.user.id, dob, addr, city, state, zip, company, phoneNumber, gender, race, isVet, branch, war, rank, troops, job, video, function (err) {
        res.redirect('/account');
    });
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

function GetCurrentProfileInformation(userId, callback) {
    var jsonArray = [];
    //acquire a connection
    pool.acquire(function (err1, connection) {
        if (err1) {
            console.log(err1);
            callback(err1, false);
        }

        var request = new Request("SELECT * FROM Users WHERE UserId=@UserId", function (err) {
            if (err) {
                console.log(err);
                connection.release();
                callback(err, false);
            }
            else {
                console.log("success");
                err = null;
                connection.release();
                if (jsonArray.length == 0) {
                    callback(err, null);
                }
                else {
                    callback(err, jsonArray);
                }
            }
        });
        request.addParameter('UserId', TYPES.NChar, userId.id);

        request.on('doneInProc', function (rowCount, more, rows) {
            rows.forEach(function (columns) {
                var rowObject = {};
                columns.forEach(function (column) {
                    if (column.value != null) {
                        rowObject[column.metadata.colName] = column.value.toString().trim();
                    }
                    else {
                        rowObject[column.metadata.colName] = null;
                    }
                });
                jsonArray.push(rowObject);
            });
        });
        connection.execSql(request);
    });
}

function InsertOrUpdateUserInDatabase(userId, famName, giveName, email, picture, lastSessionId, callback) {
    //acquire a connection
    pool.acquire(function (err1, connection) {
        if (err1) {
            console.log(err1);
            callback(err1, false);
        }

        var request = new Request("IF EXISTS (SELECT * FROM Users WHERE UserId=@UserId) UPDATE Users SET FamilyName=@FamilyName, GivenName=@GivenName, Email=@Email, Picture=@Picture, LastSessionId=@LastSessionId WHERE UserId=@UserId ELSE INSERT INTO Users (UserId, FamilyName, GivenName, Email, Picture, LastSessionId, IsVeteran) VALUES(@UserId,@FamilyName,@GivenName,@Email,@Picture,@LastSessionId, 'false')", function (err) {
            if (err) {
                console.log(err);
                connection.release();
                callback(err, false);
            }
            else {
                console.log("success");
                connection.release();
                callback(err, true);
            }
        });
        request.addParameter('UserId', TYPES.NChar, userId);
        request.addParameter('FamilyName', TYPES.NChar, famName);
        request.addParameter('GivenName', TYPES.NChar, giveName);
        request.addParameter('Email', TYPES.NChar, email);
        request.addParameter('Picture', TYPES.NChar, picture);
        request.addParameter('LastSessionId', TYPES.NChar, lastSessionId);
        connection.execSql(request);
    });
}

function PostNewItem(userId, title, cost, quantityAvailable, pickUp, image, callback)
{
    //acquire a connection
    pool.acquire(function (err1, connection) {
        if (err1) {
            console.log(err1);
            callback(err1, false);
        }
        var request = new Request("INSERT INTO Products (Title, Cost, Quantity, PickUpAvailable, MainImageLink, SellerId) VALUES(@Title,@Cost,@Quantity,@PickUpAvailable,@ImageLink,@SellerId)", function (err) {
            if (err) {
                console.log(err);
                connection.release();
                callback(err, false);
            }
            else {
                console.log("success");
                connection.release();
                callback(err, true);
            }
        });
        request.addParameter('SellerId', TYPES.NChar, userId);
        request.addParameter('ImageLink', TYPES.NChar, image);
        request.addParameter('Cost', TYPES.Float, cost);
        request.addParameter('Quantity', TYPES.NChar, quantityAvailable);
        request.addParameter('PickUpAvailable', TYPES.NChar, pickUp);
        request.addParameter('Title', TYPES.NChar, title);
        try {
            connection.execSql(request);
        }
        catch (ex) {
            console.log(ex);
        }
    });
}

function GetProducts(userId, callback) {
    var jsonArray = [];
    //acquire a connection
    pool.acquire(function (err1, connection) {
        if (err1) {
            console.log(err1);
            callback(err1, false);
        }
        try {
            var request = new Request("SELECT * FROM Products WHERE SellerId=@UserId", function (err) {
                if (err) {
                    console.log(err);
                    connection.release();
                    callback(err, false);
                }
                else {
                    console.log("success");
                    err = null;
                    connection.release();
                    if (jsonArray.length == 0) {
                        callback(err, null);
                    }
                    else {
                        callback(err, jsonArray);
                    }
                }
            });
            request.addParameter('UserId', TYPES.NChar, userId);

            request.on('doneInProc', function (rowCount, more, rows) {
                rows.forEach(function (columns) {
                    var rowObject = {};
                    columns.forEach(function (column) {
                        if (column.value != null) {
                            rowObject[column.metadata.colName] = column.value.toString().trim();
                        }
                        else {
                            rowObject[column.metadata.colName] = null;
                        }
                    });
                    jsonArray.push(rowObject);
                });
            });
            connection.execSql(request);
        }
        catch (ex) {
            console.log(ex);
        }

    });
}

function DeleteProduct(userId, id, callback) {
    //acquire a connection
    pool.acquire(function (err1, connection) {
        if (err1) {
            console.log(err1);
            callback(err1, false);
        }

        var request = new Request("IF EXISTS (SELECT * FROM Products WHERE id=@id AND SellerId=@UserId) DELETE FROM Products WHERE id=@id AND SellerId=@UserId", function (err) {
            if (err) {
                console.log(err);
                connection.release();
                callback(err, false);
            }
            else {
                console.log("success");
                connection.release();
                callback(err, true);
            }
        });
        request.addParameter('id', TYPES.NChar, id);
        request.addParameter('UserId', TYPES.NChar, userId);
        try {
            connection.execSql(request);
        }
        catch (ex) {
            console.log(ex);
        }
    });
}

function UpdateProducts(userId, title, cost, quantityAvailable, pickUp, mainimage, image2, image3, image4, image5, id, tags, callback) {
    //acquire a connection
    pool.acquire(function (err1, connection) {
        if (err1) {
            console.log(err1);
            callback(err1, false);
        }

        var request = new Request("IF EXISTS (SELECT * FROM Products WHERE id=@id AND SellerId=@UserId) UPDATE Products SET Title=@Title, Cost=@Cost, Quantity=@Quantity, PickUpAvailable=@PickUpAvailable, MainImageLink=@MainImageLink, ImageLink2=@ImageLink2, ImageLink3=@ImageLink3, ImageLink4=@ImageLink4, ImageLink5=@ImageLink5, DescriptionTags=@DescriptionTags WHERE id=@id AND SellerId=@UserId", function (err) {
            if (err) {
                console.log(err);
                connection.release();
                callback(err, false);
            }
            else {
                console.log("success");
                connection.release();
                callback(err, true);
            }
        });
        request.addParameter('UserId', TYPES.NChar, userId);
        request.addParameter('Title', TYPES.NChar, title);
        request.addParameter('Cost', TYPES.Float, cost);
        request.addParameter('Quantity', TYPES.NChar, quantityAvailable);
        request.addParameter('PickUpAvailable', TYPES.NChar, pickUp);
        request.addParameter('MainImageLink', TYPES.NChar, mainimage);
        request.addParameter('ImageLink2', TYPES.NChar, image2);
        request.addParameter('ImageLink3', TYPES.NChar, image3);
        request.addParameter('ImageLink4', TYPES.NChar, image4);
        request.addParameter('ImageLink5', TYPES.NChar, image5);
        request.addParameter('DescriptionTags', TYPES.NChar, tags);
        request.addParameter('id', TYPES.NChar, id);
        try {
            connection.execSql(request);
        }
        catch (ex) {
            console.log(ex);
        }
    });
}

function UpdateProfile(userId, dob, addr, city, state, zip, company, phoneNumber, gender, race, isVet, branch, war, rank, troops, job, video, callback) {
    //acquire a connection
    pool.acquire(function (err1, connection) {
        if (err1) {
            console.log(err1);
            callback(err1, false);
        }

        var request = new Request("IF EXISTS (SELECT * FROM Users WHERE UserId=@UserId) UPDATE Users SET DateOfBirth=@DateOfBirth, Address=@Address, City=@City, State=@State, ZipCode=@ZipCode, Gender=@Gender, Race=@Race, Company=@Company, Job=@Job, MilitaryBranch=@MilitaryBranch, OperationOrWar=@OperationOrWar, Rank=@Rank, TroopDescription=@TroopDescription, IsVeteran=@IsVeteran, VideoInterviewLink=@VideoInterviewLink WHERE UserId=@UserId", function (err) {
            if (err) {
                console.log(err);
                connection.release();
                callback(err, false);
            }
            else {
                console.log("success");
                connection.release();
                callback(err, true);
            }
        });
        request.addParameter('UserId', TYPES.NChar, userId);
        request.addParameter('DateOfBirth', TYPES.Date, dob);
        request.addParameter('Address', TYPES.NChar, addr);
        request.addParameter('City', TYPES.NChar, city);
        request.addParameter('State', TYPES.NChar, state);
        request.addParameter('ZipCode', TYPES.NChar, zip);
        request.addParameter('Gender', TYPES.NChar, gender);
        request.addParameter('Race', TYPES.NChar, race);
        request.addParameter('Company', TYPES.NChar, company);
        request.addParameter('PhoneNumber', TYPES.NChar, phoneNumber);
        request.addParameter('Job', TYPES.NChar, job);
        request.addParameter('MilitaryBranch', TYPES.NChar, branch);
        request.addParameter('OperationOrWar', TYPES.NChar, war);
        request.addParameter('Rank', TYPES.NChar, rank);
        request.addParameter('IsVeteran', TYPES.NChar, isVet);
        request.addParameter('TroopDescription', TYPES.NChar, troops);
        request.addParameter('VideoInterviewLink', TYPES.NChar, video);
        try {
            connection.execSql(request);
        }
        catch (ex) {
            console.log(ex);
        }
    });
}

module.exports = app;
https.createServer(options, app).listen(443);
http.createServer(app).listen(process.env.PORT || 80);