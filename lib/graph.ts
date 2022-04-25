import "isomorphic-fetch";
import { Client } from "@microsoft/microsoft-graph-client";
import { AuthenticationProvider, ClientOptions } from "@microsoft/microsoft-graph-client";
var config = require('./config');

// auth provider required by the MSFT graph API client 
export class MyAuthenticationProvider implements AuthenticationProvider {
    
	/**
	 * This method will get called before every request to the msgraph server
	 * This should return a Promise that resolves to an accessToken (in case of success) or rejects with error (in case of failure)
	 * Basically this method will contain the implementation for getting and refreshing accessTokens
	 */
	public async getAccessToken(): Promise<string> {

        var config = require('./config');
        
        const axios = require('axios');
        const qs = require('querystring');
        let uri = `https://login.microsoftonline.com/${config.graph.token_id}/oauth2/v2.0/token`;
        let res = await axios.post(uri, qs.stringify({
            client_id: config.graph.client_id, 
            client_secret: config.graph.client_secret,
            grant_type: "client_credentials",
            scope: "https://graph.microsoft.com/.default",
        }),{
            headers: {
                "Content-Type": "application/x-www-form-urlencoded"
            }
        });
        return res.data.access_token;
    }
}
