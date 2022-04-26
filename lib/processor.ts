import {Request, Response} from "express";  
var xml2js = require('xml2js');
var util = require('util');
const { create } = require('xmlbuilder2');
import { Client } from "@microsoft/microsoft-graph-client";
import { AuthenticationProvider, ClientOptions } from "@microsoft/microsoft-graph-client";

var config = require('./config');
import { MyAuthenticationProvider } from "./graph"; 

export default class Processor {

    public static cycle = 0;
    public static userCycle = 0;

    // Called after a device enrolls so that we send all the expected policies to it without
    // having to restart the service.
    public static ResetSession() {
        console.log("Resetting session for newly-enrolled device.");
        Processor.cycle = 0;
        Processor.userCycle = 0;
    }

    // Called to process each MDM session
    public static ProcessSession(req: Request, res: Response)
    {
        // Get the session details
        var soap = req.body;
        var aadUserToken = '';
        //console.log(util.inspect(soap, false, null));
        var sessionId = soap['SyncML']['SyncHdr'][0]['SessionID'][0];
        var target = soap['SyncML']['SyncHdr'][0]['Target'][0]['LocURI'][0];
        var source = soap['SyncML']['SyncHdr'][0]['Source'][0]['LocURI'][0];
        var messageId = soap['SyncML']['SyncHdr'][0]['MsgID'][0];
        var mode = req.query.mode;
        console.log("Session %s %s with device %s started.", mode, sessionId, source);
        
        // Build the initial response with the SyncHdr response
        var responseDoc = create({version: '1.0'})
            .ele('SyncML', { xnlns: 'SYNCML:SYNCML1.2'})
                .ele('SyncHdr')
                    .ele('VerDTD').txt('1.2').up()
                    .ele('VerProto').txt('DM/1.2').up()
                    .ele('SessionID').txt(sessionId).up()
                    .ele('MsgId').txt(messageId).up()
                    .ele('Target')
                        .ele('LocURI').txt(target).up().up()
                    .ele('Source')
                        .ele('LocURI').txt(source).up().up().up()
                .ele('SyncBody')
                    .ele('Status')
                        .ele('CmdID').txt('1').up()
                        .ele('MsgRef').txt(messageId).up()
                        .ele('CmdRef').txt('0').up()
                        .ele('Cmd').txt('SyncHdr').up()
                        .ele('Data').txt('200');

        const bodyNode = responseDoc.root().find((n: { node: { nodeName: string; }; }) => n.node.nodeName === 'SyncBody');
        var currentCommand = 1;

        // Display the command details received
        for (var command in soap['SyncML']['SyncBody'][0]) {
            var commandJson = soap['SyncML']['SyncBody'][0][command];

            switch (command)
            {
                case 'Alert': {
                    // Process each alert
                    for (const i in commandJson)
                    {
                        var commandId = commandJson[i]['CmdID'][0];
                        var alertId = commandJson[i]['Data'][0];
                        switch (alertId) {
                            case '1200': {
                                console.log('Alert 1200: Server-initiated session.');
                                break;
                            }
                            case '1201': {
                                console.log('Alert 1201: Client-initiated session.');
                                break;
                            }
                            case '1223': {
                                console.log('Alert 1223: Session abort.');
                                break;
                            }
                            case '1224':
                            case '1226': {
                                var alertType = commandJson[i]['Item'][0]['Meta'][0]['Type'][0]['_'];
                                var alertData = commandJson[i]['Item'][0]['Data'][0];
                                if (alertType == 'com.microsoft/MDM/AADUserToken')
                                {
                                    aadUserToken = alertData;
                                }
                                console.log('Alert 1224: %s', alertType, alertData);
                                break;
                            }
                            default: {
                                console.log('Alert %s: Unknown %s', alertId, util.inspect(commandJson[i]['Item'], false, null));
                            }
                        }
                        currentCommand++;
                        bodyNode.ele('Status')
                            .ele('CmdID').txt(currentCommand).up()
                            .ele('MsgRef').txt(messageId).up()
                            .ele('CmdRef').txt(commandId).up()
                            .ele('Cmd').txt('Alert').up()
                            .ele('Data').txt('200');
                    }
                    break;
                }
                case 'Replace': {
                    // Process replace
                    for (const i in commandJson[0]['Item'])
                    {
                        var current = commandJson[0]['Item'][i];
                        var replaceSource = current['Source'][0]['LocURI'][0];
                        var replaceData = current['Data'][0];
                        console.log('Replace: %s with %s', replaceSource, replaceData);
                    }
                    var commandId = commandJson[0]['CmdID'][0];
                    currentCommand++;
                    bodyNode.ele('Status')
                        .ele('CmdID').txt(currentCommand).up()
                        .ele('MsgRef').txt(messageId).up()
                        .ele('CmdRef').txt(commandId).up()
                        .ele('Cmd').txt('Replace').up()
                        .ele('Data').txt('200');
                    break;
                }
                case 'Results': {
                    // Process each result
                    for (const i in commandJson)
                    {
                        var commandId = commandJson[i]['CmdID'][0];
                        var messageId = commandJson[i]['MsgRef'][0];
                        var source = commandJson[i]['Item'][0]['Source'][0]['LocURI'][0];
                        var resultData = commandJson[i]['Item'][0]['Data'][0];
                        console.log('Result: %s = %s', source, resultData);
                    }
                    break;                    
                }
                case 'Status': {
                    // Process each status
                    for (const i in commandJson)
                    {
                        var commandId = commandJson[i]['CmdID'][0];
                        var messageId = commandJson[i]['MsgRef'][0];
                        var statusCommand = commandJson[i]['Cmd'][0];
                        var resultData = commandJson[i]['Data'][0];
                        console.log('Status: %s command reported %s', statusCommand, resultData);
                    }
                    break;                    
                }
                case 'Final': {
                    console.log('End of session');
                    break;
                }
                default: {
                    console.log('Unhandled: %s', command);
                }
            }
        }

        // Add commands for the client to process

        // Device commands first
        switch (Processor.cycle)
        {
            case 0: {
                // Set policy to poll on login
                currentCommand++;
                bodyNode.ele('Replace')
                    .ele('CmdID').txt(currentCommand).up()
                    .ele('Item')
                        .ele('Target')
                            .ele('LocURI').txt('./Vendor/MSFT/DMClient/Provider/BabyMDM/Poll/PollOnLogin').up().up()
                        .ele('Meta')
                            .ele('Format', {xmlns: 'syncml:metinf'}).txt('bool').up()
                            .ele('Type', {xmlns: 'syncml:metinf'}).txt('text/plain').up().up()
                        .ele('Data').txt('true');
                console.log('Command: Replace PollOnLogin');

                // Set PFN for WNS
                currentCommand++;
                bodyNode.ele('Replace')
                    .ele('CmdID').txt(currentCommand).up()
                    .ele('Item')
                        .ele('Target')
                            .ele('LocURI').txt('./Vendor/MSFT/DMClient/Provider/BabyMDM/Push/PFN').up().up()
                        .ele('Data').txt('1728KaroshiWare.BabyMDM');
                console.log('Command: Replace PFN');

                // Turn off Hello for Business
                bodyNode.ele('Replace')
                    .ele('CmdID').txt(currentCommand).up()
                    .ele('Item')
                        .ele('Target')
                            .ele('LocURI').txt('./Vendor/MSFT/PassportForWork/f28cef80-3f9b-49d7-921e-81b2bf60fd6c/Policies/UsePassportForWork').up().up()
                        .ele('Meta')
                            .ele('Format', {xmlns: 'syncml:metinf'}).txt('bool').up()
                            .ele('Type', {xmlns: 'syncml:metinf'}).txt('text/plain').up().up()
                        .ele('Data').txt('false');
                console.log('Command: Replace UsePassportForWork');

                // Turn off first logon animation
                bodyNode.ele('Replace')
                .ele('CmdID').txt(currentCommand).up()
                .ele('Item')
                    .ele('Target')
                        .ele('LocURI').txt('./Device/Vendor/MSFT/Policy/Config/WindowsLogon/EnableFirstLogonAnimation').up().up()
                    .ele('Meta')
                        .ele('Format', {xmlns: 'syncml:metinf'}).txt('int').up()
                        .ele('Type', {xmlns: 'syncml:metinf'}).txt('text/plain').up().up()
                    .ele('Data').txt('0');
                console.log('Command: Replace EnableFirstLogonAnimation');

                // Set a Windows 11 Start menu layout
                currentCommand++;
                bodyNode.ele('Replace')
                    .ele('CmdID').txt(currentCommand).up()
                    .ele('Item')
                        .ele('Target')
                            .ele('LocURI').txt('./Vendor/MSFT/Policy/Config/Start/ConfigureStartPins').up().up()
                        .ele('Data').txt('{ "pinnedList": [ { "desktopAppId": "MSEdge" } ] }');
                console.log('Command: Replace ConfigureStartPins');
                
                // Ask for for the device architecture
                currentCommand++;
                bodyNode.ele('Get')
                    .ele('CmdID').txt(currentCommand).up()
                    .ele('Item')
                        .ele('Target')
                            .ele('LocURI').txt('./DevDetail/Ext/Microsoft/ProcessorArchitecture');
                console.log('Command: Get PollOnLogin');

                // Ask for the AAD device ID
                currentCommand++;
                bodyNode.ele('Get')
                .ele('CmdID').txt(currentCommand).up()
                .ele('Item')
                    .ele('Target')
                        .ele('LocURI').txt('./Vendor/MSFT/DMClient/Provider/BabyMDM/AADDeviceID');
                console.log('Command: Get AADDeviceID');

                // Ask for the Autopilot hardware hash
                currentCommand++;
                bodyNode.ele('Get')
                    .ele('CmdID').txt(currentCommand).up()
                    .ele('Item')
                        .ele('Target')
                            .ele('LocURI').txt('./DevDetail/Ext/DeviceHardwareData');        
                console.log('Command: Get DeviceHardwareData (Autopilot hash)');


                // Add the MSI to install
                currentCommand++;
                bodyNode.ele('Add')
                    .ele('CmdID').txt(currentCommand).up()
                    .ele('Item')
                        .ele('Target')
                            .ele('LocURI').txt('./Device/Vendor/MSFT/EnterpriseDesktopAppManagement/MSI/%7B23170F69-40C1-2702-1900-000001000000%7D/DownloadInstall');
                console.log('Command: Add 7Zip MSI');
                // Execute the installation
                // SHA-256 hash generated using "shasum -a 256 7z1900-x64.msi" or "Get-FileHash" in PowerShell
                var installJob = create()
                currentCommand++;
                bodyNode.ele('Exec')
                    .ele('CmdID').txt(currentCommand).up()
                    .ele('Item')
                        .ele('Target')
                            .ele('LocURI').txt('./Device/Vendor/MSFT/EnterpriseDesktopAppManagement/MSI/%7B23170F69-40C1-2702-1900-000001000000%7D/DownloadInstall').up().up()
                        .ele('Meta')
                            .ele('Format', {xmlns: 'syncml:metinf'}).txt('xml').up()
                            .ele('Type', {xmlns: 'syncml:metinf'}).txt('text/plain').up().up()
                        .ele('Data')
                            .ele('MsiInstallJob', {id: '{23170F69-40C1-2702-1900-000001000000}'})
                            .ele('Product', {Version: '7.8.9'})
                                .ele('Download')
                                    .ele('ContentURLList')
                                        .ele('ContentURL').txt(config.service.url + '/7z1900-x64.msi').up().up().up()
                                .ele('Validation')
                                    .ele('FileHash').txt('A7803233EEDB6A4B59B3024CCF9292A6FFFB94507DC998AA67C5B745D197A5DC').up().up()
                                .ele('Enforcement')
                                    .ele('CommandLine').txt('/qn').up()
                                    .ele('RetryCount').txt('3').up()
                                    .ele('RetryInterval').txt('5');
                console.log('Command: Exec 7Zip MSI');
                
                // Remove Power Automate Desktop in-box app
                currentCommand++;
                bodyNode.ele('Exec')
                    .ele('CmdID').txt(currentCommand).up()
                    .ele('Item')
                        .ele('Target')
                            .ele('LocURI').txt('./Device/Vendor/MSFT/EnterpriseModernAppManagement/AppManagement/RemovePackage').up().up()
                        .ele('Meta')
                            .ele('Format', {xmlns: 'syncml:metinf'}).txt('xml').up().up()
                        .ele('Data')
                            .ele('Package', { Name: 'Microsoft.PowerAutomateDesktop_10.0.561.0_neutral_~_8wekyb3d8bbwe', RemoveForAllUsers: '1' })
                console.log('Command: Remove Power Automate Desktop app');

                // Remove Your Phone in-box app
                currentCommand++;
                bodyNode.ele('Exec')
                    .ele('CmdID').txt(currentCommand).up()
                    .ele('Item')
                        .ele('Target')
                            .ele('LocURI').txt('./Device/Vendor/MSFT/EnterpriseModernAppManagement/AppManagement/RemovePackage').up().up()
                        .ele('Meta')
                            .ele('Format', {xmlns: 'syncml:metinf'}).txt('xml').up().up()
                        .ele('Data')
                            .ele('Package', { Name: 'Microsoft.YourPhone_2019.430.2026.0_neutral_~_8wekyb3d8bbwe', RemoveForAllUsers: '1' })
                console.log('Command: Remove Your Phone app');

                // Remove Cortana in-box app
                currentCommand++;
                bodyNode.ele('Exec')
                    .ele('CmdID').txt(currentCommand).up()
                    .ele('Item')
                        .ele('Target')
                            .ele('LocURI').txt('./Device/Vendor/MSFT/EnterpriseModernAppManagement/AppManagement/RemovePackage').up().up()
                        .ele('Meta')
                            .ele('Format', {xmlns: 'syncml:metinf'}).txt('xml').up().up()
                        .ele('Data')
                            .ele('Package', { Name: 'Microsoft.549981C3F5F10_2.2106.2807.0_neutral_~_8wekyb3d8bbwe', RemoveForAllUsers: '1' })
                console.log('Command: Remove Cortana app');
                
                // Tell ESP to track the MSI
                currentCommand++;
                bodyNode.ele('Replace')
                    .ele('CmdID').txt(currentCommand).up()
                    .ele('Item')
                        .ele('Target')
                            .ele('LocURI').txt('./Device/Vendor/MSFT/DMClient/Provider/BabyMDM/FirstSyncStatus/ExpectedMSIAppPackages').up().up()
                        .ele('Data').txt('./Device/Vendor/MSFT/EnterpriseDesktopAppManagement/MSI/%7B23170F69-40C1-2702-1900-000001000000%7D/Status;1');
                console.log('Command: Replace ExpectedMSIAppPackages');
                
                // Tell ESP to track a policy
                currentCommand++;
                bodyNode.ele('Replace')
                    .ele('CmdID').txt(currentCommand).up()
                    .ele('Item')
                        .ele('Target')
                            .ele('LocURI').txt('./Device/Vendor/MSFT/DMClient/Provider/BabyMDM/FirstSyncStatus/ExpectedPolicies').up().up()
                        .ele('Data').txt('./Device/Vendor/MSFT/DMClient/Provider/BabyMDM/EntDMID');
                console.log('Command: Replace ExpectedPolicies');
                
                // Tell ESP that we're done sending policies
                currentCommand++;
                bodyNode.ele('Replace')
                    .ele('CmdID').txt(currentCommand).up()
                    .ele('Item')
                        .ele('Target')
                            .ele('LocURI').txt('./Device/Vendor/MSFT/DMClient/Provider/BabyMDM/FirstSyncStatus/ServerHasFinishedProvisioning').up().up()
                        .ele('Meta')
                            .ele('Format', {xmlns: 'syncml:metinf'}).txt('bool').up()
                            .ele('Type', {xmlns: 'syncml:metinf'}).txt('text/plain').up().up()
                        .ele('Data').txt('true');
                console.log('Command: Replace ServerHasFinishedProvisioning');
                break;
            }
        }

        // User commands next.  I only want to tell ESP it is done.
        if (aadUserToken != '' && Processor.userCycle == 0)
        {
            currentCommand++;
            bodyNode.ele('Replace')
                .ele('CmdID').txt(currentCommand).up()
                .ele('Item')
                    .ele('Target')
                        .ele('LocURI').txt('./User/Vendor/MSFT/DMClient/Provider/BabyMDM/FirstSyncStatus/ServerHasFinishedProvisioning').up().up()
                    .ele('Meta')
                        .ele('Format', {xmlns: 'syncml:metinf'}).txt('bool').up()
                        .ele('Type', {xmlns: 'syncml:metinf'}).txt('text/plain').up().up()
                    .ele('Data').txt('true');
            console.log('Command: User: Replace ServerHasFinishedProvisioning');
            Processor.userCycle++;
        }

        Processor.cycle++;

        bodyNode.ele('Final');

        // Now send the response
        var xmlString = responseDoc.end({group: true, prettyPrint: true});
        //console.log(xmlString);

        res.set('Content-Type', 'application/vnd.syncml.dm+xml');
        res.status(200).send(xmlString);
    }
}       
