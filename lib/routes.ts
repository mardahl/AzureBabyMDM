// /lib/routes.ts
import {request, Request, Response} from "express";  
import {DOMParser, XMLSerializer} from 'xmldom';
var xmlparser = require('express-xml-bodyparser');
var util = require('util');
var xml2js = require('xml2js');
var fs = require('fs');
var forge = require('node-forge');
var crypto = require('crypto');
import { Client, TelemetryHandler } from "@microsoft/microsoft-graph-client";
import { AuthenticationProvider, ClientOptions } from "@microsoft/microsoft-graph-client";
var querystring = require('querystring');

var config = require('./config');
import processor from "./processor";
import { MyAuthenticationProvider } from "./graph"; 

function GetPrivateKey(keyPath: string)
{
    var pem  = fs.readFileSync(keyPath, 'utf8');
    return forge.pki.privateKeyFromPem(pem);
}

function GetCert(certPath: string) {

    var pem  = fs.readFileSync(certPath, 'utf8');
    var cert = forge.pki.certificateFromPem(pem);
    return EncodeCert(cert);
}

function EncodeCert(c: any)
{
    // Get the binary certificate (DER)
    var d = forge.asn1.toDer(forge.pki.certificateToAsn1(c));

    // Encode it as base64
    var encoded = forge.util.encode64(d.getBytes());

    // Calculate the cert fingerprint (SHA-1 hash).  (Couldn't get forge to do this correctly.)
    var hash = crypto.createHash('sha1');
    hash.update(encoded, 'base64');
    var hex = hash.digest('hex');

    console.log("Fingerprint: " + hex)
    console.log("Encoded cert:");
    console.log(encoded);

    return { cert: c, encodedCert: encoded, fingerprint: hex, cn: c.subject.getField('CN').value };
}

function GetAttributes(soap: any)
{
    var rawContext = soap['s:Envelope']['s:Body'][0]['wst:RequestSecurityToken'][0]['ac:AdditionalContext'][0]['ac:ContextItem'];
    var cleanContext: { [key: string]: any[]} = {};
    for (const i in rawContext)
    {
        cleanContext[rawContext[i]['$']['Name']] = rawContext[i]['ac:Value'][0];
    }
    console.info(cleanContext);
    return cleanContext;
}

export class Routes {       
    public routes(app: any): void {          
        app.route('/')
        .get((req: Request, res: Response) => {      

            console.log('Unexpected request:');
            console.dir(req);

            res.status(200).send({
                message: 'GET request successfull!!!!'
            })
        }) 
        
        app.route("/tou")
        .get((req: Request, res: Response) => {
            // Process TOU page request
            console.log("=== TOU:")
            //console.info(req.get('Authorization'));
            console.log('Request mode "%s" with ID: %s', req.query.mode, req.query["client-request-id"]);

            // Decode the bearer token as a JWT
            var payloadEncoded = req.get('Authorization').split('.')[1];
            const payload = Buffer.from(payloadEncoded, 'base64');
            var jwt = JSON.parse(payload.toString('utf-8'));
            //console.info(jwt);
            console.log('User: %s %s', jwt.upn, jwt.name);
            console.log('App ID: %s %s', jwt.appid, jwt.aud);

            // Display the page
            res.render("tou", {"redirect_uri" : req.query.redirect_uri, "token": req.get('Authorization'), "req": req.query["client-request-id"], "mode": req.query.mode})
        })

        app.route('/EnrollmentServer/Discovery.svc')
        .get((req: Request, res: Response) => {
            // Discovery GET request, just report back a 200.  The client should then respond
            // with a POST.
            console.log('=== DISCOVER GET');
            res.status(200).send();
        })

        app.route(["/discover","/EnrollmentServer/Discovery.svc"])
        .post((req: Request, res: Response) => {
            // Process discover request
            console.log('=== DISCOVER POST:');
            //console.log(util.inspect(req.body, false, null));
            var soap = req.body;
            var messageId = soap['s:Envelope']['s:Header'][0]['a:MessageID'][0];
            var email = soap['s:Envelope']['s:Body'][0]['Discover'][0]['request'][0]['EmailAddress'][0];
            var deviceType = soap['s:Envelope']['s:Body'][0]['Discover'][0]['request'][0]['DeviceType'][0];
            var osVersion = soap['s:Envelope']['s:Body'][0]['Discover'][0]['request'][0]['ApplicationVersion'][0];
            var osEdition = soap['s:Envelope']['s:Body'][0]['Discover'][0]['request'][0]['OSEdition'][0];
            console.log('Message ID: %s', messageId);
            console.log('User: %s', email);
            console.log('OS: %s version = %s edition = %s', deviceType, osVersion, osEdition);

            // Create the response from a template
            var template  = fs.readFileSync('discovery.xml', 'utf8');

            // Edit the references
            var re = /MYURL/gm;
            var template = template.replace(re, config.service.url);
            //console.log(xmlString);

            // Send the response
            res.set('Content-Type', 'application/soap+xml');
            res.status(200).send(template);
        })

        app.route("/enrollment")
        .post((req: Request, res: Response) => {
            // Process an enrollment request
            console.log('=== ENROLL:');
            //console.log(util.inspect(req.body, false, null));
            var soap = req.body;

            // Get the message ID
            var messageID = soap['s:Envelope']['s:Header'][0]['a:MessageID'][0];
            console.log('Message ID: %s', messageID);

            // Get the JWT token and decode it
            var tokenEncoded = soap['s:Envelope']['s:Header'][0]['wsse:Security'][0]['wsse:BinarySecurityToken'][0]['_'];
            const buff = Buffer.from(tokenEncoded, 'base64');
            var payloadEncoded = buff.toString('utf-8').split('.')[1];
            const payload = Buffer.from(payloadEncoded, 'base64');
            var jwt = JSON.parse(payload.toString('utf-8'));
            console.log(util.inspect(jwt, false, null));
            console.log('User: %s %s', jwt.upn, jwt.name);
            console.log('App ID: %s %s', jwt.appid, jwt.aud);
            console.log('AAD device ID: %s', jwt.deviceid);

            // Determine what to respond with
            var doc;
            if (soap['s:Envelope']['s:Body'][0]['wst:RequestSecurityToken'])
            {
                console.log("*** Request security token")

                // Get the additional context values
                var context : any = GetAttributes(soap);

                // Determine the certificate store based on the EnrollmentType.  With 'device"
                // enrollments (most common), it should be a machine cert, while for 'full'
                // enrollments (used with Add Work Account enrollments) it should be a user cert.
                var myStore = 'User';
                if (context['EnrollmentType'] == 'Device')
                {
                    myStore = 'System';
                }
                console.log('Certificate store: %s', myStore);
            
                // Get the certificate signing request from the body
                var csrEncoded = soap['s:Envelope']['s:Body'][0]['wst:RequestSecurityToken'][0]['wsse:BinarySecurityToken'][0]['_'];

                // Get the certs (TODO only root)
                var sslCert = GetCert(config.service.certificate);
                //console.log("*** SSL cert:");
                //console.log(util.inspect(sslCert, false, null));

                var sslKey = GetPrivateKey(config.service.privateKey);
                //console.log("*** SSL private key:");
                //console.log(util.inspect(sslKey, false, null));
                
                // Generate a certificate
                var csr = forge.pki.certificationRequestFromPem('-----BEGIN CERTIFICATE REQUEST-----\n' + csrEncoded + '\n-----END CERTIFICATE REQUEST-----\n');
                //console.log("*** CSR:");
                //console.log(util.inspect(csr, false, null));

                var cn = [
                    {name: 'commonName', value: context['DeviceID']}
                ]
                var extensions = [ 
                    {name: 'keyUsage', digitalSignature: true}, 
                    {name: 'extKeyUsage', clientAuth: true}
                ];
                var cert = forge.pki.createCertificate();
                cert.publicKey = csr.publicKey;
                cert.serialNumber = '01';
                cert.validity.notBefore = new Date();
                cert.validity.notAfter = new Date();
                cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear()+1);
                cert.setSubject(cn);
                cert.setIssuer(sslCert.cert.issuer.attributes);
                cert.sign(sslKey);
                cert.setExtensions(extensions);
                cert.signature = csr.signature;
                cert.sign(sslKey, forge.md.sha256.create());
                var encodedClient = EncodeCert(cert);
                //console.log("*** New cert:");
                //console.log(util.inspect(encodedClient, false, null));

                // Create the security token response from a template
                var template  = fs.readFileSync('securitytoken.xml', 'utf8');
                doc = new DOMParser().parseFromString(template);

                // Create the security token response from a template
                var wapTemplate = fs.readFileSync('wap.xml');
                var wapString = new String(wapTemplate);
                
                // Edit the references in the WAP
                var re = /ROOTTHUMB/gm;
                wapString = wapString.replace(re, sslCert.fingerprint);
                re = /ROOTCERT/gm;
                wapString = wapString.replace(re, sslCert.encodedCert);
                var re = /MYSTORE/gm;
                wapString = wapString.replace(re, myStore);
                var re = /MYTHUMB/gm;
                wapString = wapString.replace(re, encodedClient.fingerprint);
                re = /MYCERT/gm;
                wapString = wapString.replace(re, encodedClient.encodedCert);
                re = /MYCN/gm;
                wapString = wapString.replace(re, encodedClient.cn);
                re = /MYURL/gm;
                wapString = wapString.replace(re, config.service.url);
                //console.log("*** WAP string: " + wapString);

                // Edit the response
                var childs = doc.documentElement.getElementsByTagName('BinarySecurityToken');
                var wapBuff = Buffer.from(wapString); 
                childs[0].textContent = wapBuff.toString('base64');

                // Update Graph to indicate the device is managed and compliant
                if (jwt.deviceid)
                {
                    console.log('Patching device %s', jwt.deviceid);
                    let clientOptions: ClientOptions = {
                        authProvider: new MyAuthenticationProvider()
                    };
                    const client = Client.initWithMiddleware(clientOptions);

                    // Get the right device because we need the id value (not the deviceid)
                    client.api('/devices')
                    .filter(`deviceid eq '${jwt.deviceid}'`)
                    .get()
                    .then (getRes => {

                        // Issue the patch
                        const objid:string = getRes.value[0].id;
                        client.api(`/devices/${objid}`)
                            .patch({
                                "isCompliant": true,
                                "isManaged": true
                            }).then (patchRes => {
                                // normally this is undefined as patch doesn't return any results 
                                console.log(patchRes);
                            });
                    });
                }            
                else
                {
                    console.log('Unable to patch, no device ID.');
                }
            }
            else if (soap['s:Envelope']['s:Body'][0]['GetPolicies'])
            {
                console.log("*** Get policies")
                // Create the policy response from a template
                var template  = fs.readFileSync('policies.xml', 'utf8');
                doc = new DOMParser().parseFromString(template);

                // Edit the response
                // TODO
            }
            else
            {
                // No match
                console.log("*** No match");
                res.status(500).send();
                return;
            }
            // Send the response
            var xmlString = new XMLSerializer().serializeToString(doc);
            // console.log(xmlString);
            res.set('Content-Type', 'application/soap+xml');
            res.status(200).send(xmlString);            
        })

        app.route("/cimhandler")
        .post((req: Request, res: Response) => {
            // Process a normal MDM sync session (cimhandler)
            console.log('=== CIMHANDLER:');
            //console.log(util.inspect(req.body, false, null));
            
            // Process the session
            processor.ProcessSession(req, res);
        })

        app.route("/login")
        .get((req: Request, res: Response) => {
            // Redirect to AAD to complete the authentication
            console.log('=== LOGIN GET')
            var redirectUrl:string = config.service.url;
            var redirect = querystring.escape(`${redirectUrl}/login`);
            var nonce = crypto.randomBytes(16).toString('base64');
            console.log(redirect);
            var url = `https://login.windows.net/common/oauth2/authorize?client_id=${config.graph.client_id}&nonce=${nonce}&redirect_uri=${redirect}&response_mode=form_post&response_type=id_token&scope=openid&state=${req.query.appru}&login_hint=${req.query.login_hint}&username=${req.query.username}`;
            console.log('Redirect: %s', url);
            res.redirect(url);
        })

        app.route("/login")
        .post((req: Request, res: Response) => {
            // Receive the token from AAD and redirect it to the discovery URL
            console.log('=== LOGIN POST')
            var body = req.body;
            console.dir(body);

            // Send a page with the token
            res.render("login", {"token" : body.id_token});
        })
    }
}
