var fs = require('fs');
var http = require('http');
var config = require('./config');

// lib/server.ts
import app from "./app";

var httpServer = http.createServer(app);

httpServer.listen(80);
