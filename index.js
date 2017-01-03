var dbname = 'app-d2121ee08caf832b73a160f9ea022ad9';
//var dbname = 'test1';
var express = require('express');
var http = require('http');
var config = require('./config.json');
var gm = require('gm');
var socketIo = require('socket.io');
var socketio_jwt = require('socketio-jwt');
var uuid = require('uuid');
var jwt = require('jsonwebtoken');
var jwt_secret = config.secret;
var nodemailer = require('nodemailer');
var transport = nodemailer.createTransport(config.transport);
var valuepath = function (input, doc) {
    var path = input.split('/'),
        item = doc,
        m,
        key;
    for (m = 1; m < path.length; m += 1) {
        key = path[m];
        if (item.hasOwnProperty(key)) {
            item = item[key];
        } else {
            return null;
        }

    }
    return item;
};
var testrules = function (rules, doc) {
    var key,
        rule;
    for (key in rules) {
        if (rules.hasOwnProperty(key)) {
            rule = rules[key];
            if (Object.prototype.toString.call(rule) === '[object Array]') {
                if (rule.indexOf(valuepath(key, doc)) === -1) {
                    return false;
                }
            } else if (rule !== valuepath(key, doc)) {
                return false;
            }
        }
    }
    return true;
};
var sendmail = function (email, subject) {
    return function (err, html, text) {
        if (err) {
            console.log(err);
        } else {
            console.log('sendmail: ' + email + ' ' + subject);
            transport.sendMail({
                from: config.transport.auth.user,
                to: email,
                subject: subject,
                html: html,
                text: text
            }, function (err, responseStatus) {
                if (err) {
                    console.log(err);
                }
            });
        }
    };
};
/*var nano = require('nano')({
    "url": config.url,
    "parseUrl": false
});*/
var nano = require('nano')({
    url: 'http://' + config.couchdb.host + ':' + config.couchdb.port5984,
    requestDefaults: {
        auth: {
            user: config.couchdb.user,
            pass: config.couchdb.password
        }
    }
});
var db_admin = nano.db.use("admin");
var emailTemplates = require('email-templates');
var path = require('path');
//var templatesDir = path.join(__dirname, 'emailtemplates');
var templatesDir = "/mnt/gluster/emailtemplates";



var work = function (emailoptions, doc, template) {
    db_admin.view('database', 'emailtemplate', emailoptions, function (err, data) {
        if (err) {
            console.log("view");
            console.log(err);
        } else {
            data.rows.forEach(function (row) {
                var key, ok, item, email;
                if (row.doc.users) {
                    for (key in row.doc.users) {
                        if (row.doc.users.hasOwnProperty(key)) {
                            item = row.doc.users[key];
                            ok = testrules(item.rules, doc);
                            if (ok) {
                                template(row.id, {
                                    doc: doc,
                                    env: config.env
                                }, sendmail(key, row.doc.name));
                            }
                        }
                    }
                }
                if (row.doc.userfields) {
                    for (key in row.doc.userfields) {
                        if (row.doc.userfields.hasOwnProperty(key)) {
                            email = valuepath(key, doc);
                            item = row.doc.userfields[key];
                            ok = testrules(item.rules, doc);
                            if (ok && email) {
                                template(row.id, {
                                    doc: doc,
                                    env: config.env
                                }, sendmail(email, row.doc.name));
                            }
                        }
                    }
                }
            });
        }
    });
};


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
function removeDoc(db, id, rev) {
    return new Promise(function (resolve, reject) {
        db.destroy(id, rev, function (err, body) {
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
                    h: doc.hidden,
                    b: doc.description
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
    //console.log('emit', name);
    createEmitData(db, id, emitHidden).then(function (data) {
        data.s = seq
        socket.emit(name, data);
    }).catch(function (err) {
        console.log(err);
    });
}
function emitDatabase(name, db, id, seq, socket) {
    //console.log('emit', name, id);
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
            emitDatabase(name, db, '_design/schema', seq, socket);
        }
    }
    if (changes.hasOwnProperty('_design/straks')) {
        if (changes['_design/straks'].hasOwnProperty('deleted')) {
            socket.emit(name, {
                '_id': '_design/straks',
                d: true
            });
        } else {
            emitDatabase(name, db, '_design/straks', seq, socket);
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
                emitDatabase(name, db, id, seq, socket);
            }
        }
    }
}
function getAll(socket, options) {
    return Promise.resolve().then(function () {
        socket.join(options.name);
        if (options.changes.since[0] === '[') {
            options.changes.since = '0';
        }
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
function thumbnail(name, attachment) {
    return new Promise(function (resolve, reject) {
        var source = name;
        if (attachment.content_type === 'image/jpeg') {
            source = source + '.jpg';
        } else if (attachment.content_type === 'image/png') {
            source = source + '.png';
        }
        gm(attachment.data, source).resize(100, 100).toBuffer('JPG', function (err, buffer) {
            if (err) {
                reject(err);
            } else {
                resolve({ name: 'tn_' + name, data: buffer, content_type: 'image/jpeg' });
            }
        });
    });
}
var testExpire = function (socket) {
    if (socket.hasOwnProperty('decoded_token')) {
        console.log(Date.now() / 1000, socket.decoded_token);
        if (Date.now() / 1000 > socket.decoded_token.exp) {
            socket.emit('unauthenticated');
            console.log('unauthenticated');
        }
    }
}
emailTemplates(templatesDir, function (err, template) {
    if (err) {
        console.log(err);
    } else {


        sio.sockets.on('connection', function (socket) {
            if (socket.hasOwnProperty('decoded_token')) {
                //console.log('authenticated', socket.decoded_token);
                socket.emit('authenticated', { token: socket.token, profile: socket.decoded_token });

            }
            //console.log(socket.decoded_token.email, 'connected');
            socket.on('queue', function (data) {
                console.log('queue', data);
                testExpire(socket);
                var dbname = 'db-' + data.db;
                var db = nano.db.use(dbname);
                var emailoptions = {
                    reduce: false,
                    include_docs: true
                };
                if (data.d) {
                    getDoc(db, data._id).then(function (doc) {
                        emailoptions.key = [data.db, "delete"];
                        work(emailoptions, doc, template);
                        return removeDoc(db, data._id, doc._rev);
                    }).then(function (doc) {
                        socket.emit('queue', data._id);
                        sio.to(dbname).emit(dbname + '-check', {});
                    }).catch(function (err) {
                        console.log(err);
                    })
                } else {
                    var doc = {};
                    var attachments = [];
                    var thumbnails = [];
                    for (var key in data.doc) {
                        if (key === '_attachments') {
                            for (var name in data.doc._attachments) {
                                var attachment = data.doc._attachments[name];
                                if (attachment.hasOwnProperty('data')) {
                                    attachments.push({ name: name, data: attachment.data, content_type: attachment.content_type });
                                    thumbnails.push(thumbnail(name, attachment));
                                }
                            }

                        } else {
                            doc[key] = data.doc[key];
                        }
                    }
                    Promise.all(thumbnails).then(function (res) {
                        return new Promise(function (resolve, reject) {
                            for (var i = 0; i < res.length; i++) {
                                attachments.push(res[i]);
                            }
                            var id = doc.hasOwnProperty('_id') ? doc._id : data._id;
                            console.log(id);
                            if (attachments.length > 0) {
                                console.log('insert multipart');
                                db.multipart.insert(doc, attachments, id, function (err, body) {
                                    console.log('after insert multipart');
                                    resolve({ err: err, body: body });
                                });
                            } else {
                                console.log('insert');
                                db.insert(data.doc, id, function (err, body) {
                                    console.log('after insert insert');
                                    resolve({ err: err, body: body });
                                });
                            }
                        });
                    }).then(function (res) {
                        console.log('after insert',res);
                        if (res.err) {
                            console.log(res.err);
                        } else {
                            sio.to(dbname).emit(dbname + '-check', {});
                        }
                        socket.emit('queue', data._id);
                        getDoc(db, data._id).then(function (doc) {
                            var rev = doc._rev.split('-');
                            if (rev[0] === '1') {
                                emailoptions.key = [data.db, "create"];
                                console.log('created: ' + doc._id);
                            } else {
                                emailoptions.key = [data.db, "update"];
                                console.log('updated: ' + doc._id);
                            }
                            work(emailoptions, doc, template);

                        }).catch(function (err) {
                            console.log(err);
                        });
                    });
                }
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
            socket.on('unauthenticate', function (data) {
                if (socket.hasOwnProperty('token')) {
                    delete socket.token;
                }
                socket.emit('unauthenticated', 'logout');
            });
            socket.on('forgot', function (email) {
                var db = require('nano')({
                    url: 'http://' + config.couchdb.host + ':' + config.couchdb.port5986 + '/_users',
                    requestDefaults: {
                        auth: {
                            user: config.couchdb.user,
                            pass: config.couchdb.password
                        }
                    }
                });

                db.get('org.couchdb.user:' + email, function (err, body) {
                    if (err) {
                        console.log(err);
                        socket.emit('forgot', 'Brugeren findes ikke.');
                    } else {
                        var code = uuid.v1();
                        body.verification_code = code;
                        db.insert(body, body._id, function (err, body) {
                            if (err) {
                                socket.emit('forgot', err);
                            } else {
                                template('forgot', {
                                    url: config.forgot.url + code
                                }, function (err, html, text) {
                                    if (err) {
                                        socket.emit('forgot', err);
                                    } else {
                                        transport.sendMail({
                                            from: config.forgot.from,
                                            to: email,
                                            subject: 'Nulstil password',
                                            html: html,
                                            text: text
                                        }, function (err, responseStatus) {
                                            if (err) {
                                                socket.emit('forgot', err);
                                            } else {
                                                socket.emit('forgot', 'Der er sendt en mail til ' + email + '.');
                                            }
                                        });
                                    }
                                });
                            }
                        });
                    }
                });
            });
            socket.on('thumbnail', function (data) {
                testExpire(socket);
                var db = nano.db.use(data.d);
                getAttachment(db, data.i, 'tn_' + data.n).then(function (result) {
                    socket.emit('thumbnail', { a: data, b: result });
                })

            });
            socket.on('join', function (data) {
                testExpire(socket);
                console.log('join', data);
                for (var i = 0; i < data.length; i++) {
                    var dbname = data[i];
                    socket.join(dbname);
                    socket.emit(dbname + '-check', {});
                }
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
                        since: data.s,
                        include_docs: true
                    }
                };
                getAll(this, options).then(function (result) {
                    //emitDatabaseAll(options.name, options.db, socket, result);
                    socket.emit(options.name, result);
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
            socket.on('configuration-list-rev', function (data) {
                testExpire(socket);
                socket.join('configuration-list-' + data.o + '/' + data.i);
                var db = nano.db.use(dbname + '-' + data.o);
                if (data.i && data.i !== '') {
                    headDoc(db, data.i).then(function (etag) {
                        if (etag !== data.r) {
                            //return getDoc(db, data.i, { attachments: true });
                            return createEmitData(db, data.i, true);
                        }
                        return null;
                    }).then(function (doc) {
                        if (doc) {
                            /*if (doc.hasOwnProperty('_attachments')) {
                                for (var key in doc._attachments) {
                                    var attachment = doc._attachments[key];
                                    if (attachment.content_type === 'application/json') {
                                        var json = new Buffer(doc._attachments[key].data, 'base64').toString('utf8');
                                        doc._attachments[key].data = JSON.parse(json);
                                    } else {
                                        doc._attachments[key].data = new Buffer(doc._attachments[key].data, 'base64');
                                    }
                                }
                            }*/
                            socket.emit('configuration-list-' + data.o + '/' + data.i, doc);
                        }
                    }).catch(function (err) {
                        socket.emit('configuration-list-' + data.o + '/' + data.i, { '_id': data.i, 'd': true });
                    });
                }
            });
        });
    }
});
server.listen(9000, function () {
    console.log('listening on http://localhost:9000');
});
