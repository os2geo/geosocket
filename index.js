var dbname = 'app-d2121ee08caf832b73a160f9ea022ad9';
//var dbname = 'test1';
var express = require('express');
var http = require('http');
var config = require('./config.json');

var socketIo = require('socket.io');
var socketio_jwt = require('socketio-jwt');

var jwt = require('jsonwebtoken');
var jwt_secret = config.secret;

var nano = require('nano')({
    "url": config.url,
    "parseUrl": false
});

var app = express();

var serveStatic = require('serve-static');
var bodyParser = require('body-parser');

app.use(serveStatic('public', {
    'index': ['index.html']
}));
app.use(bodyParser.json());

app.get('/login/:email/:password', function (req, res) {
    res.set('Access-Control-Allow-Origin', '*');
    res.set('Access-Control-Allow-Methods', 'GET');
    res.set('Access-Control-Allow-Headers', 'accept, authorization, content-type, origin, referer');
    if (!req.params.email && !req.params.password) {
        console.log('mangler email og password')
        //res.set('WWW-Authenticate', 'Basic realm=Authorization Required');
        return res.sendStatus(401);
    }
    nano.auth(req.params.email, req.params.password, function (err, body, headers) {

        if (err) {
            console.log(err);
            //res.set('WWW-Authenticate', 'Basic realm=Authorization Required');
            return res.sendStatus(401);
        }
        var profile = {
            name: req.params.email
        };
        var token = jwt.sign(profile, jwt_secret, {
            expiresIn: 60 * 60 * 24
        });

        res.json({
            token: token,
            profile: profile
        });
    });



    // We are sending the profile inside the token

});

var server = http.createServer(app);
var sio = socketIo.listen(server);

/*sio.use(socketio_jwt.authorize({
    secret: jwt_secret,
    handshake: true
}));*/

function authorize() {


    var auth = {
        secret: jwt_secret,
        success: function (data, accept) {
            if (data.request) {
                accept();
            } else {
                accept(null, true);
            }
        },
        fail: function (error, data, accept) {
            if (data.request) {
                accept(error);
            } else {
                accept(null, false);
            }
        }
    };

    return function (data, accept) {
        var token, error;
        var req = data.request || data;
        /*var authorization_header = (req.headers || {}).authorization;
    
        if (authorization_header) {
          var parts = authorization_header.split(' ');
          if (parts.length == 2) {
            var scheme = parts[0],
              credentials = parts[1];
    
            if (scheme.toLowerCase() === 'bearer') {
              token = credentials;
            }
          } else {
            error = new UnauthorizedError('credentials_bad_format', {
              message: 'Format is Authorization: Bearer [token]'
            });
            return auth.fail(error, data, accept);
          }
        }*/

        //get the token from query string
        if (req._query && req._query.token) {
            token = req._query.token;
        }
        else if (req.query && req.query.token) {
            token = req.query.token;
        } else if (data.token) {
            token = data.token;
        }

        if (!token) {

            return auth.success({}, accept);
        }

        jwt.verify(token, auth.secret, function (err, decoded) {

            /*if (err) {
              error = new UnauthorizedError('invalid_token', err);
              return auth.fail(error, data, accept);
            }*/
            if (!err) {
                data.decoded_token = decoded;
            }
            auth.success(data, accept);
        });
    };
}

sio.use(authorize());

function changes(name, options) {
    return new Promise(function (resolve, reject) {
        nano.db.changes(name, options, function (err, body) {
            if (err) {
                reject(err);
            } else {
                resolve(body);
            }
        });
    });
}
function getAttachment(db, id, name) {
    return new Promise(function (resolve, reject) {
        db.attachment.get(id, name, function (err, body) {
            if (err) {
                reject(err);
            } else {
                resolve(body);
            }
        });
    });
}
function getDoc(db, id, options) {
    return new Promise(function (resolve, reject) {
        var opt = options || {};
        db.get(id, opt, function (err, body) {

            if (err) {
                reject(err);
            } else {
                resolve(body);
            }
        });
    });
}
function headDoc(db, id) {
    return new Promise(function (resolve, reject) {
        db.head(id, function (err, body, headers) {
            if (err) {
                reject(err);
            } else {
                resolve(headers.etag.substring(1, headers.etag.length - 1));
            }
        });
    });
}
function createEmitData(db, id, emitHidden) {
    return getDoc(db, id).then(function (doc) {
        var data;
        if (doc.hasOwnProperty('hidden') && doc.hidden) {
            data = {
                '_id': doc._id,
                d: true
            };
            if (emitHidden) {
                return Promise.resolve(data);
            } else {
                return Promise.reject(data);
            }
        } else {
            return Promise.resolve().then(function () {
                data = {
                    '_id': doc._id,
                    r: doc._rev,
                    n: doc.name,
                    h: doc.hidden
                }
                if (doc.hasOwnProperty('_attachments') && doc._attachments.hasOwnProperty('logo')) {
                    data.t = doc._attachments.logo.content_type;
                    return getAttachment(db, id, 'logo').then(function (logo) {
                        data.l = logo;
                        return data;
                    })
                }

                return data;
            });
        }
    });
}
function emit(name, db, id, seq, socket, emitHidden) {
    console.log('emit', name);
    createEmitData(db, id, emitHidden).then(function (data) {
        data.s = seq
        socket.emit(name, data);
    }).catch(function (err) {
        console.log(err);
    });
}
function emitDatabase(name, db, id, seq, socket) {
    console.log('emit', name, id);
    return getDoc(db, id).then(function (doc) {
        doc.s = seq;
        socket.emit(name, doc);
    }).catch(function (err) {
        console.log(err);
    });
}
function emitAll(name, dbname, socket, result) {
    var changes = result.changes;
    var seq = result.seq;
    var db = nano.db.use(dbname);
    for (var id in changes) {
        if (id !== '_design/schema' && id !== '_design/straks') {
            if (changes[id].hasOwnProperty('deleted')) {
                socket.emit(name, {
                    '_id': id,
                    d: true
                });
            } else {
                emit(name, db, id, seq, socket, true);
            }
        }
    }
}
function emitDatabaseAll(name, dbname, socket, result) {
    var changes = result.changes;
    var seq = result.seq;
    var db = nano.db.use(dbname);
    if (changes.hasOwnProperty('_design/schema')) {
        if (changes['_design/schema'].hasOwnProperty('deleted')) {
            socket.emit(name, {
                '_id': '_design/schema',
                d: true
            });
        } else {
            emitDatabase(name, db, '_design/schema', seq, socket, true);
        }
    }
    if (changes.hasOwnProperty('_design/straks')) {
        if (changes['_design/straks'].hasOwnProperty('deleted')) {
            socket.emit(name, {
                '_id': '_design/straks',
                d: true
            });
        } else {
            emitDatabase(name, db, '_design/straks', seq, socket, true);
        }
    }
    for (var id in changes) {
        if (id !== '_design/schema' && id !== '_design/straks') {
            if (changes[id].hasOwnProperty('deleted')) {
                socket.emit(name, {
                    '_id': id,
                    d: true
                });
            } else {
                emitDatabase(name, db, id, seq, socket, true);
            }
        }
    }
}
function getAll(socket, options) {
    return Promise.resolve().then(function () {
        socket.join(options.name);

        return changes(options.db, options.changes);
    }).then(function (body) {
        var result = { seq: JSON.stringify(body.last_seq), changes: {} };
        for (var i = 0; i < body.results.length; i++) {
            var doc = body.results[i];
            if (doc.id.charAt(0) !== '_' || doc.id === '_design/schema' || doc.id === '_design/straks') {
                if (options.changes.since === '0') {
                    if (result.changes.hasOwnProperty(doc.id)) {
                        if (doc.hasOwnProperty('deleted')) {
                            delete result.changes[doc.id];
                        } else {
                            result.changes[doc.id] = doc;
                        }
                    } else if (!doc.hasOwnProperty('deleted')) {
                        result.changes[doc.id] = doc;
                    }
                } else {
                    result.changes[doc.id] = doc;
                }
            }
        }

        return result;
    });
};
var testExpire = function (socket) {
    if (socket.hasOwnProperty('decoded_token')) {
        console.log(Date.now() / 1000, socket.decoded_token);
        if (Date.now() / 1000 > socket.decoded_token.exp) {
            socket.emit('unauthenticated');
            console.log('unauthenticated');
        }
    }
}

sio.sockets.on('connection', function (socket) {
    if (socket.hasOwnProperty('decoded_token')) {
        console.log('authenticated', socket.decoded_token);
        socket.emit('authenticated', { token: socket.token, profile: socket.decoded_token });

    }
    socket.emit('rune');
    console.log('connection');
    //console.log(socket.decoded_token.email, 'connected');
    socket.on('queue', function (data) {
        testExpire(socket);
        console.log(data);
    });
    socket.on('authenticate', function (data) {
        if (data.hasOwnProperty('t')) {
            jwt.verify(data.t, jwt_secret, function (err, decoded) {

                if (err) {
                    socket.emit('unathenticated', err);
                }
                else {
                    socket.emit('authenticated', {
                        token: data.t,
                        profile: decoded
                    });
                }

            });
        } else if (data.hasOwnProperty('n') && data.hasOwnProperty('p')) {
            nano.auth(data.n, data.p, function (err, body, headers) {
                if (err) {
                    socket.emit('unathenticated', err);
                } else {
                    var profile = {
                        name: data.n
                    };
                    var token = jwt.sign(profile, jwt_secret, {
                        expiresIn: 60 * 60 * 24
                    });
                    socket.emit('authenticated', {
                        token: token,
                        profile: profile
                    });
                    socket.token = token;
                }
            });
        }
    });
    socket.on('thumbnail', function (data) {
        testExpire(socket);
        var db = nano.db.use(data.d);
        getAttachment(db, data.i, 'tn_' + data.n).then(function (result) {
            socket.emit('thumbnail', { a: data, b: result });
        })

    });
    socket.on('configuration-list-all', function (data) {
        testExpire(socket);
        var options = {
            name: 'configuration-list-' + data.i,
            db: dbname + '-' + data.i,
            changes: {
                since: data.s
            }
        };
        getAll(this, options).then(function (result) {
            emitAll(options.name, options.db, socket, result);
        });
    });
    socket.on('organization-all', function (data) {
        console.log('on organization-all');
        testExpire(socket);
        var options = {
            name: 'organization',
            db: dbname,
            changes: {
                since: data.s,
                filter: 'config/config'
            }
        };
        getAll(this, options).then(function (result) {
            emitAll(options.name, options.db, socket, result);
        });
    });
    socket.on('database-all', function (data) {
        testExpire(socket);
        var options = {
            name: data.d,
            db: data.d,
            changes: {
                since: data.s
            }
        };
        getAll(this, options).then(function (result) {
            emitDatabaseAll(options.name, options.db, socket, result);
        });
    });
    socket.on('configuration-rev', function (data) {
        testExpire(socket);
        socket.join('configuration-' + data.i);
        var db = nano.db.use(dbname);
        if (data.i && data.i !== '') {
            headDoc(db, data.i).then(function (etag) {
                if (etag !== data.r) {
                    return getDoc(db, data.i, { attachments: true });
                }
                return null;
            }).then(function (doc) {
                if (doc) {
                    if (doc.hasOwnProperty('_attachments')) {
                        for (var key in doc._attachments) {
                            var attachment = doc._attachments[key];
                            if (attachment.content_type === 'application/json') {
                                var json = new Buffer(doc._attachments[key].data, 'base64').toString('utf8');
                                doc._attachments[key].data = JSON.parse(json);
                            } else {
                                doc._attachments[key].data = new Buffer(doc._attachments[key].data, 'base64');
                            }
                        }
                    }
                    socket.emit('configuration', doc);
                }
            }).catch(function (err) {
                socket.emit('configuration', { '_id': data.i, 'deleted': true });
            });
        }
    });
});

server.listen(9000, function () {
    console.log('listening on http://localhost:9000');
});
