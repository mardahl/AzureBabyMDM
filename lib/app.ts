// lib/app.ts
import express from "express";
import * as bodyParser from "body-parser";
import { Routes } from "./routes";

class App {

    public app: express.Application;
    public routes: Routes = new Routes();
    constructor() {
        this.app = express();
        this.config();        
        this.routes.routes(this.app);
    }

    private config(): void{
        // support static content
        this.app.use(express.static('static'));
        // support application/json type post data
        this.app.use(bodyParser.json());
        //support application/x-www-form-urlencoded post data
        this.app.use(bodyParser.urlencoded({ extended: false }));
        // support XML body
        var xmlparser = require('express-xml-bodyparser');
        var xml2jsDefaults = {
            explicitArray: true,
            normalize: false,
            normalizeTags: false,
            trim: true
        };
        this.app.use(xmlparser(xml2jsDefaults));
        // use Pug for HTML pages
        this.app.set('view engine', 'pug');
    }

}

export default new App().app;