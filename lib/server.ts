var fs = require('fs');
var http = require('http');
var https = require('https');
var config = require('./config');

// lib/server.ts
import app from "./app";

var privateKey  = fs.readFileSync(config.service.privateKey, 'utf8');
var certificate = fs.readFileSync(config.service.certificate, 'utf8');
var httpServer = http.createServer(app);
var credentials = {key: privateKey, cert: certificate};
var httpsServer = https.createServer(credentials, app);

httpServer.listen(80);
httpsServer.listen(443);
