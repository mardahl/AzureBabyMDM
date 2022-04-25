var http = require('http');

// lib/server.ts
import app from "./app";

var httpServer = http.createServer(app);

httpServer.listen(8080);
