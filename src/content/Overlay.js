/* ***** BEGIN LICENSE BLOCK ******
 * Version: MPL 1.1 *
 * The contents of this file are subject to the Mozilla Public License Version
 * 1.1 (the "License"); you may not use this file except in compliance with
 *  the License. You may obtain a copy of the License at * http://www.mozilla.org/MPL/
 *
 *  Software distributed under the License is distributed on an "AS IS" basis,
 *  WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
 *  for the specific language governing rights and limitations under the
 *  License.
 *
 *  The Original Code is HTTPS Finder.
 *
 *  The Initial Developer of the Original Code is Kevin Jacobs.
 *  Portions created by the Initial Developer are Copyright (C) 2011
 *  the Initial Developer. All Rights Reserved.
 *
 *  Contributor(s): Translators - see install.rdf for updated list.
 *
 *  ***** END LICENSE BLOCK *****
 */

"use strict";

if(typeof window.hfCI == "undefined") const hfCI = Components.interfaces;
if(typeof window.hfCC == "undefined") const hfCC = Components.classes;
if(typeof window.hfCU == "undefined") const hfCU = Components.utils;
if(typeof window.hfCR == "undefined") const hfCR = Components.results;



const httpsfinder_INCLUDE = function(name, targetObj) {   
    let LOADER = hfCC["@mozilla.org/moz/jssubscript-loader;1"].getService(hfCI.mozIJSSubScriptLoader);
    try {
        LOADER.loadSubScript("chrome://httpsfinder/content/"
            + name + ".js", targetObj);              
    } catch(e) {
        dump("httpsfinder INCLUDE " + name + ": " + e + "\n");
    }
}

if (!httpsfinder) var httpsfinder = {
    prefs: null, //prefs object for httpsfinder branch
    strings: null, //Strings object for httpsfinder strings
    history: null, //History observer object (clears results when history is cleared)
    debug: null, //verbose logging bool
    pbs: null//check private browsing status before saving Detection results
};


//Overlay handles most 'browser' code (including alerts except those generated from Detection, importing whitelist, startup/shutdown, etc)
httpsfinder.Overlay = {
    redirectedTab: [[]], //Tab info for pre-redirect URLs.
    recent: [[]], //Recent auto-redirects used for detecting http->https->http redirect loops. Second subscript holds the tabIndex of the redirect
    lastRecentReset: null, //time counter for detecting redirect loops

    //Window start up - set listeners, read in whitelist, etc
    
      
    init: function(){
        hfCU.import("resource://hfShared/hfShared.js", httpsfinder);

        var prefs = hfCC["@mozilla.org/preferences-service;1"]
        .getService(hfCI.nsIPrefBranch);
        httpsfinder.prefs =  prefs.getBranch("extensions.httpsfinder.");

        httpsfinder.Cookies = {};
        httpsfinder.Detect = {};
        httpsfinder_INCLUDE('Cookies', httpsfinder.Cookies);
        httpsfinder_INCLUDE('HTTPSDetect', httpsfinder.Detect);

        //pref change observer
        httpsfinder.prefs.QueryInterface(hfCI.nsIPrefBranch2);
        httpsfinder.prefs.addObserver("", this, false);
        
        if(!httpsfinder.prefs.getBoolPref("enable"))
            return;

        //History observer
        var hs = hfCC["@mozilla.org/browser/nav-history-service;1"].
        getService(hfCI.nsINavHistoryService);
        hs.addObserver(httpsfinder.history, false);

        //Used for auto-dismissing alerts (auto-dismiss timer is started when user clicks on a tab, so they don't miss background alerts)
        var container = gBrowser.tabContainer;
        container.addEventListener("TabSelect", httpsfinder.Overlay.tabChangedListener, false);

        //Listener is used for displaying HTTPS alerts after a page is loaded
        var appcontent = document.getElementById("appcontent");
        if(appcontent)
            appcontent.addEventListener("load", httpsfinder.Overlay.onPageLoadListener, true);

        //Used to check private browsing status before caching Detection results
        httpsfinder.pbs = hfCC["@mozilla.org/privatebrowsing;1"]
        .getService(hfCI.nsIPrivateBrowsingService);
        
        //Register HTTP observer for HTTPS Detection
        httpsfinder.Detect.register();
        httpsfinder.Cookies.register();

        httpsfinder.strings = document.getElementById("httpsfinderStrings");
        if(httpsfinder.prefs == null || httpsfinder.strings == null){
            dump("httpsfinder cannot load Preferences or strings - init() failed\n");
            return;
        }
         
        var installedVersion = httpsfinder.prefs.getCharPref("version");
        var firstrun = httpsfinder.prefs.getBoolPref("firstrun");
        httpsfinder.debug = httpsfinder.prefs.getBoolPref("debugLogging");

        //Try/catch attempts to recreate db table (in case it has been deleted). Doesn't overwrite though
        try{
            //Create whitelist database
            var file = hfCC["@mozilla.org/file/directory_service;1"]
            .getService(hfCI.nsIProperties)
            .get("ProfD", hfCI.nsIFile);
            file.append("httpsfinder.sqlite");
            var storageService = hfCC["@mozilla.org/storage/service;1"]
            .getService(hfCI.mozIStorageService);
            var mDBConn = storageService.openDatabase(file); //Creates db on first run.
            mDBConn.createTable("whitelist", "rule STRING NOT NULL UNIQUE");

        }catch(e){
            //NS_ERROR_FAILURE is thrown when we try to recreate a table (May be too generic though...))
            if(e.name != 'NS_ERROR_FAILURE')
                hfCU.reportError("HTTPS Finder: initialize error " + e + "\n");
        }
        finally{
            mDBConn.close();
            var currentVersion = httpsfinder.strings.getString("httpsfinder.version");
            if (firstrun){
                //First run code
                httpsfinder.prefs.setBoolPref("firstrun",false);
                httpsfinder.prefs.setCharPref("version", currentVersion);
            }
            else if (installedVersion != currentVersion && !firstrun){
                //Upgrade code
                httpsfinder.prefs.setCharPref("version",currentVersion);
                httpsfinder.Overlay.importWhitelist();
            }
            else //All other startup
                httpsfinder.Overlay.importWhitelist();
        }
    },

    //Auto-dismiss alert timers are started after the user clicks over to the given tab, so the
    //user doesn't miss background alerts that are dismissed before they switch to the tab.
    tabChangedListener: function(event){
        if(!httpsfinder.prefs.getBoolPref("dismissAlerts"))
            return;

        var browser = gBrowser.selectedBrowser;
        var alerts = ["httpsfinder-restart", "httpsfinder-ssl-enforced", "httpsfinder-https-found"];

        for(var i=0; i < alerts.length; i++){
            var key = alerts[i];
            //If the tab contains that alert, set a timeout and removeNotification() for the auto-dismiss time.
            if (item = window.getBrowser().getNotificationBox(browser).getNotificationWithValue(key)){
                setTimeout(function(){
                    httpsfinder.removeNotification(key)
                },httpsfinder.prefs.getIntPref("alertDismissTime") * 1000);
                return;
            }
        }
    },
    
    /*
    * onPageLoadListener checks for any HTTPS redirect/Detection activity for the tab. If there is something that the user needs to be alerted of,
    * The notification is added. We can't add the notification directly from the Detection callback, because page content still being loaded
    * causes the notifications to be automatically dismissed from time to time. This is basically a method to slow down alerts until the page is ready.
    */
    onPageLoadListener: function(aEvent) {
        var brow = gBrowser.getBrowserForDocument(aEvent.originalTarget);
        var index = gBrowser.getBrowserIndexForDocument(aEvent.originalTarget);
        if(typeof httpsfinder.Overlay.redirectedTab[index] == "undefined" ||
            typeof httpsfinder.Overlay.redirectedTab[index][0] == "undefined" ||
            typeof httpsfinder.Overlay.redirectedTab[index][1] == "undefined" ||
            brow.currentURI.scheme != "https" || brow == null)
            return;

        var tabHost = brow.currentURI.host;
        var storedHost = httpsfinder.Overlay.redirectedTab[index][1].host;
        if(httpsfinder.Overlay.getHostWithoutSub(tabHost) != httpsfinder.Overlay.getHostWithoutSub(storedHost)){
            //Alert was for a previous tab and was not dismissed (page change timed just right before alert was cleared
            httpsfinder.Overlay.redirectedTab[index] = new Array();
            if(httpsfinder.debug)
                dump("httpsfinder resetting alert for tab - host mismatch on " + tabHost  +  " and "  + storedHost + "\n");
            return;
        }

        //If user was redirected - Redirected array holds at [x][0] a bool for whether or not the tab index has been redirected.
        //[x][1] holds a string hostname for the pre-redirect URL.  This is necessary because some sites like Google redirect to
        //encrypted.google.com when you use HTTPS.  We have to remember the old URL so it can be whitelisted from the alert drop down.
        if(httpsfinder.Overlay.redirectedTab[index][0]){
            if(!httpsfinder.prefs.getBoolPref("noruleprompt"))
                httpsfinder.Overlay.alertSSLEnforced(aEvent.originalTarget);
            httpsfinder.Overlay.redirectedTab[index][0] = false;
        }
    },

    //Return host without subdomain (e.g. input: code.google.com, outpout: google.com)
    getHostWithoutSub: function(fullHost){
        if(typeof fullHost != 'string')
            return "";
        else
            return fullHost.slice(fullHost.indexOf(".") + 1, fullHost.length);
    },

    importWhitelist: function(){
        //Can we get rid of these loops and just reset length? Test in Ubuntu**(wasn't working before without loops)
        for(var i=0; i <  httpsfinder.results.whitelist.length; i++)
            httpsfinder.results.whitelist[i] = "";
        httpsfinder.results.whitelist.length = 0;

        for(i=0; i <  httpsfinder.results.goodSSL.length; i++)
            httpsfinder.results.goodSSL[i] = "";
        httpsfinder.results.goodSSL.length = 0;

        for(i=0; i <  httpsfinder.results.tempNoAlerts.length; i++)
            httpsfinder.results.tempNoAlerts[i] = "";
        httpsfinder.results.tempNoAlerts.length = 0;

        try{
            var file = hfCC["@mozilla.org/file/directory_service;1"]
            .getService(hfCI.nsIProperties)
            .get("ProfD", hfCI.nsIFile);
            file.append("httpsfinder.sqlite");
            var storageService = hfCC["@mozilla.org/storage/service;1"]
            .getService(hfCI.mozIStorageService);
            var mDBConn = storageService.openDatabase(file);
            var statement = mDBConn.createStatement("SELECT rule FROM whitelist");

            statement.executeAsync({
                handleResult: function(aResultSet){
                    for (let row = aResultSet.getNextRow(); row; row = aResultSet.getNextRow()){
                        httpsfinder.results.whitelist.push(row.getResultByName("rule"));
                    }
                },

                handleError: function(anError){
                    dump("httpsfinder whitelist database error " + anError.message + "\n");
                },

                handleCompletion: function(aReason){
                    //differentiate between permanent and temp whitelist items - permanent items are the first
                    // 'x' entries in the whitelist array. Temp items are added later as x+1....x+n
                    httpsfinder.results.permWhitelistLength = httpsfinder.results.whitelist.length;

                    if (aReason != hfCI.mozIStorageStatementCallback.REASON_FINISHED)
                        dump("httpsfinder database error " + aReason.message + "\n");
                    else if(httpsfinder.prefs.getBoolPref("whitelistChanged"))
                        httpsfinder.prefs.setBoolPref("whitelistChanged", false);
                }
            });
        }
        catch(e){
            hfCU.reportError("HTTPS Finder: load whitelist " + e.name + "\n");
        }
        finally{
            statement.reset();
            mDBConn.asyncClose()
        }
    },

    tempWhitelistDomain: function(hostIn){        
        httpsfinder.Cookies.restoreDefaultCookiesForHost(hostIn);
        httpsfinder.results.whitelist.push(hostIn);
    },


    //User clicked "Add to whitelist" from a drop down notification. Save to sqlite and whitelist array.
    whitelistDomain: function(hostIn){
        //Manually remove notification - in Ubuntu it stays up (no error is thrown)
        httpsfinder.removeNotification('httpsfinder-https-found');
        httpsfinder.removeNotification('httpsfinder-ssl-enforced');       
        

        //If no host was passed, get it manually from stored values.
        if(typeof(hostIn) != "string"){
            var hostname;
            if(typeof httpsfinder.Overlay.redirectedTab[gBrowser.getBrowserIndexForDocument(gBrowser.contentDocument)] != "undefined" &&
                typeof httpsfinder.Overlay.redirectedTab[gBrowser.getBrowserIndexForDocument(gBrowser.contentDocument)][1] != "undefined" )
                hostname = httpsfinder.Overlay.redirectedTab[gBrowser.getBrowserIndexForDocument(gBrowser.contentDocument)][1].host.toLowerCase();
            else
                hostname = gBrowser.currentURI.host.toLowerCase();

            //Bug workaround.  If user closes tab in the middle of open tabs, the indexes are shifted.  The only time we can't just use currentURI
            //is when the https:// page forwards to a subdomain.  This is rare.  With the for loop below, this bug can still happen, but only under the following conditions:
            //1) Auto forward enabled. 2)User browsed to a site where HTTPS forwards to a different hostname 3)conditions 1 and 2 are done in a background tab
            //4) Some tab before the above tab is closed, then user switches to the target tab and clicks "Add to whitelist".  This is unlikely enough that I'm leaving
            //it in for now.  Will look for a better way to do this than the redirectedTab array.
            for(var i=0; i<httpsfinder.Overlay.redirectedTab.length; i++){
                if(typeof httpsfinder.Overlay.redirectedTab[i] == "undefined" || typeof httpsfinder.Overlay.redirectedTab[i][1] == "undefined")
                    hostname = hostname; //do nothing
                else if(httpsfinder.Overlay.redirectedTab[i][1].host.toLowerCase() == gBrowser.currentURI.host.toLowerCase())
                    hostname = gBrowser.currentURI.host.toLowerCase();
            }
        }
        else if(typeof(hostIn) == "string")
            hostname = hostIn;

        httpsfinder.Cookies.restoreDefaultCookiesForHost(hostname);

        try{
            var file = hfCC["@mozilla.org/file/directory_service;1"]
            .getService(hfCI.nsIProperties)
            .get("ProfD", hfCI.nsIFile);
            file.append("httpsfinder.sqlite");
            var storageService = hfCC["@mozilla.org/storage/service;1"]
            .getService(hfCI.mozIStorageService);
            var mDBConn = storageService.openDatabase(file);

            var statement = mDBConn.createStatement("INSERT INTO whitelist (rule) VALUES (?1)");
            statement.bindStringParameter(0, hostname);
            statement.executeAsync({
                handleResult: function(aResultSet){},

                handleError: function(anError){
                    alert("Error adding rule: " + anError.message);
                    dump("httpsfinder whitelist rule add error " + anError.message + "\n");
                },
                handleCompletion: function(aReason){
                    if (aReason == hfCI.mozIStorageStatementCallback.REASON_FINISHED)
                        if(!httpsfinder.Overlay.isWhitelisted(hostname) &&
                            !httpsfinder.pbs.privateBrowsingEnabled){
                            httpsfinder.results.whitelist.push(hostname);
                        }
                }
            });
        }
        catch(e){
            hfCU.reportError("HTTPS Finder: addToWhitelist " + e.name + "\n");
        }
        finally{
            statement.reset();
            mDBConn.asyncClose()
        }
    },

    //Alert after HTTPS was auto-enforced on a page
    alertSSLEnforced: function(aDocument){
        var browser = gBrowser.getBrowserForDocument(aDocument);

        var host = null;
        try{
            host = gBrowser.currentURI.host;
        }
        catch(e){}

        //Return if a rule has already been saved this session (we just silently enforce)
        if(httpsfinder.results.tempNoAlerts.indexOf(browser.currentURI.host) != -1)
            return;

        //Append alert if 'noruleeprompt' pref is not enabled, and host is not "". (addon manager, blank page, etc)
        else if(!httpsfinder.prefs.getBoolPref("noruleprompt") && host != ""){

            var nb = gBrowser.getNotificationBox(gBrowser.getBrowserForDocument(aDocument));
            var saveRuleButtons = [{
                label: httpsfinder.strings.getString("httpsfinder.main.whitelist"),
                accessKey: httpsfinder.strings.getString("httpsfinder.main.whitelistKey"),
                popup: null,
                callback: httpsfinder.Overlay.whitelistDomain
            },{
                label: httpsfinder.strings.getString("httpsfinder.main.noThanks"),
                accessKey: httpsfinder.strings.getString("httpsfinder.main.noThanksKey"),
                popup: null,
                callback: httpsfinder.Overlay.redirectNotNow
            },{
                label: httpsfinder.strings.getString("httpsfinder.main.rememberSetting"),
                accessKey: httpsfinder.strings.getString("httpsfinder.main.rememberSettingKey"),
                popup: null,
                callback: httpsfinder.Overlay.writeRule
            }];

            if(httpsfinder.prefs.getBoolPref("autoforward"))
                nb.appendNotification(httpsfinder.strings.getString("httpsfinder.main.autoForwardRulePrompt"),
                    "httpsfinder-ssl-enforced", 'chrome://httpsfinder/skin/httpsAvailable.png',
                    nb.PRIORITY_INFO_HIGH, saveRuleButtons);
            else
                nb.appendNotification(httpsfinder.strings.getString("httpsfinder.main.saveRulePrompt"),
                    "httpsfinder-ssl-enforced", 'chrome://httpsfinder/skin/httpsAvailable.png',
                    nb.PRIORITY_INFO_HIGH, saveRuleButtons);

            if(httpsfinder.prefs.getBoolPref("dismissAlerts"))
                setTimeout(function(){
                    httpsfinder.removeNotification("httpsfinder-ssl-enforced")
                },httpsfinder.prefs.getIntPref("alertDismissTime") * 1000, 'httpsfinder-ssl-enforced');
        }
    },

    //Check if host is whitelisted (permanently by user, not by us). Checks permanently whitelisted items.
    isPermWhitelisted: function(host){
        for(var i = 0; i < httpsfinder.results.permWhitelistLength; i++){
            var whitelistItem = httpsfinder.results.whitelist[i];
            if(whitelistItem == host)
                return true;

            //If rule starts with *., check the end of the hostname (i.e. for *.google.com, check for host ending in .google.com
            else if(whitelistItem.substr(0,2) == "*.")
                //Delete * from rule, compare to last "rule length" chars of the hostname
                if(whitelistItem.replace("*","") == host.substr(host.length -
                    whitelistItem.length + 1,host.length))
                    return true;
        }
        return false;
    },


    //Check if host is whitelisted. Checks permanently whitelisted items and session items.
    isWhitelisted: function(host){
        for(var i=0; i < httpsfinder.results.whitelist.length; i++){
            var whitelistItem = httpsfinder.results.whitelist[i];
            if(whitelistItem == host)
                return true;

            //If rule starts with *., check the end of the hostname (i.e. for *.google.com, check for host ending in .google.com
            else if(whitelistItem.substr(0,2) == "*.")
                //Delete * from rule, compare to last "rule length" chars of the hostname
                if(whitelistItem.replace("*","") == host.substr(host.length -
                    whitelistItem.length + 1,host.length))
                    return true;
        }
        return false;
    },

    //Save rule for HTTPS Everywhere. We do a little work here, then pass
    //to the function provided by hfShared (the preference window uses the same code)
    writeRule: function(){
        var eTLDService = hfCC["@mozilla.org/network/effective-tld-service;1"]
        .getService(hfCI.nsIEffectiveTLDService);

        var topLevel = null;
        try{
            //Try retrieving the pre-redirect host from the redirected array
            topLevel = "." + eTLDService.getPublicSuffix(httpsfinder.Overlay.redirectedTab[gBrowser.getBrowserIndexForDocument(gBrowser.contentDocument)][1]);
            var hostname = httpsfinder.Overlay.redirectedTab[gBrowser.getBrowserIndexForDocument(gBrowser.contentDocument)][1].host.toLowerCase();
        }
        catch(e){
            //If that fails (It shouldn't), grab the currentURI
            hostname = gBrowser.currentURI.host.toLowerCase();
            topLevel =  "." + eTLDService.getPublicSuffixFromHost(hostname);
        }

        httpsfinder.sharedWriteRule(hostname, topLevel, "");
    },

    //Adds to session whitlelist (not database)
    redirectNotNow: function() {
        var hostname = "";
        if(typeof httpsfinder.Overlay.redirectedTab[gBrowser.getBrowserIndexForDocument(gBrowser.contentDocument)] != "undefined" &&
            typeof httpsfinder.Overlay.redirectedTab[gBrowser.getBrowserIndexForDocument(gBrowser.contentDocument)][1] != "undefined" )
            hostname = httpsfinder.Overlay.redirectedTab[gBrowser.getBrowserIndexForDocument(gBrowser.contentDocument)][1].host.toLowerCase();
        else
            hostname = gBrowser.currentURI.host.toLowerCase();

        //Bug workaround.  If user closes tab in the middle of open tabs, the indexes are shifted.  The only time we can't just use currentURI
        //is when the https:// page forwards to a subdomain.  This is rare.  With the for loop below, this bug can still happen, but only under the following conditions:
        //1) Auto forward enabled. 2)User browsed to a site where HTTPS forwards to a different hostname 3)conditions 1 and 2 are done in a background tab
        //4) Some tab before the above tab is closed, then user switches to the target tab and clicks "Add to whitelist".  This is unlikely enough that I'm leaving
        //it in for now.  Will look for a better way to do this than the redirectedTab array.
        for(var i=0; i<httpsfinder.Overlay.redirectedTab.length; i++){
            if(typeof httpsfinder.Overlay.redirectedTab[i] == "undefined" ||
                typeof httpsfinder.Overlay.redirectedTab[i][1] == "undefined")
                hostname = hostname; //do nothing
            else if(httpsfinder.Overlay.redirectedTab[i][1].host.toLowerCase() ==
                gBrowser.currentURI.host.toLowerCase())
                hostname = gBrowser.currentURI.host.toLowerCase();
        }
        if(!httpsfinder.Overlay.isWhitelisted(hostname) && !httpsfinder.pbs.privateBrowsingEnabled)
            httpsfinder.Overlay.tempWhitelistDomain(hostname);
    },

    //Auto-redirect to https
    redirectAuto: function(aBrowser, request){
        var sinceLastReset = Date.now() - httpsfinder.Overlay.lastRecentReset;
        var index = gBrowser.getBrowserIndexForDocument(aBrowser.contentDocument);
        var requestURL = request.URI.asciiSpec.replace("http://", "https://");
        var host = request.URI.host.toLowerCase();

        var redirectLoop = false;
        ///Need to determine if link was clicked, or if reload is automatic
        if(sinceLastReset < 2500 && sinceLastReset > 200){
            for(var i=0; i<httpsfinder.Overlay.recent.length; i++){
                if(httpsfinder.Overlay.recent[i][0] == host && httpsfinder.Overlay.recent[i][1] == index){
                    if(!httpsfinder.Overlay.isWhitelisted(host) &&
                        !httpsfinder.pbs.privateBrowsingEnabled)                        
                        httpsfinder.Overlay.tempWhitelistDomain(host);

                    for(let i = 0; i < httpsfinder.results.goodSSL.length; i++){
                        if(httpsfinder.results.goodSSL[i] == host){
                            httpsfinder.results.goodSSL.splice(i,1);
                            return;
                        }
                    }

                    dump("httpsfinder redirect loop detected on host " + host + ". Host temporarily whitelisted. Reload time: " + sinceLastReset + "ms\n");
                    redirectLoop = true;
                }
            }
            httpsfinder.Overlay.recent.length = 0;
        }

        if(httpsfinder.Detect.hostsMatch(aBrowser.contentDocument.baseURIObject.host.toLowerCase(),host) && !redirectLoop){
            aBrowser.loadURIWithFlags(requestURL, nsIWebNavigation.LOAD_FLAGS_REPLACE_HISTORY);
            httpsfinder.Overlay.redirectedTab[index] = new Array();
            httpsfinder.Overlay.redirectedTab[index][0] = true;
            httpsfinder.Overlay.redirectedTab[index][1] = aBrowser.currentURI;

            httpsfinder.Overlay.removeFromWhitelist(aBrowser.contentDocument, request.URI.host.toLowerCase());
        }
        else{
            if(httpsfinder.debug && !redirectLoop)
                dump("Host mismatch, forward blocked (Document: " +
                    aBrowser.contentDocument.baseURIObject.host.toLowerCase() +
                    " , Detection host: " + host + "\n");
        }

        httpsfinder.Overlay.recent.push([host,index]);
        httpsfinder.Overlay.lastRecentReset = Date.now();
    },

    //Manual redirect (user clicked "Yes, go HTTPS")
    redirect: function() {
        var aDocument = gBrowser.contentDocument;
        httpsfinder.Overlay.redirectedTab[gBrowser.getBrowserIndexForDocument(aDocument)] = new Array();
        httpsfinder.Overlay.redirectedTab[gBrowser.getBrowserIndexForDocument(aDocument)][0] = true;

        var ioService = hfCC["@mozilla.org/network/io-service;1"]
        .getService(hfCI.nsIIOService);

        var uri = gBrowser.getBrowserForDocument(aDocument).currentURI.asciiSpec;
        uri = uri.replace("http://", "https://");

        httpsfinder.Overlay.redirectedTab[gBrowser.getBrowserIndexForDocument(aDocument)][1] = ioService.newURI(uri, null, null);
        window.content.wrappedJSObject.location = uri;
    },

    // Removes item from the session whitelist array. This is messy and needs to be fixed.
    // Runes three ways and is called from multiple functions.
    removeFromWhitelist: function(aDocument, host){
        // Check for passed in hostname (if calling function called removeFromWhitelist(null, "xxxxxx.com")
        if(!aDocument && host)
            for(let i=0; i<httpsfinder.results.whitelist.length; i++){
                if(httpsfinder.results.whitelist[i] == host){
                    if(httpsfinder.debug)
                        dump("1 httpsfinder removing " + httpsfinder.results.whitelist[i] + " from whitelist\n");
                    httpsfinder.results.whitelist.splice(i,1);
                }
            }

        // Else, if called as removeFromWhitelist(tab.contentDocument, null) - get the host and remove that from the whitelist
        else if(aDocument && !host){
            var preRedirectHost = gBrowser.getBrowserForDocument(aDocument).currentURI.host;
            for(let i=0; i<httpsfinder.results.whitelist.length; i++){
                if(httpsfinder.results.whitelist[i] == preRedirectHost.slice((preRedirectHost.length - httpsfinder.results.whitelist[i].length),preRedirectHost.length)){
                    if(httpsfinder.debug)
                        dump("2 httpsfinder removing " + httpsfinder.results.whitelist[i] + " from whitelist\n");
                    httpsfinder.results.whitelist.splice(i,1);

                }
            }
        }

        // Catch for any thing that slipped through... Why is this needed? Maybe if "gBrowser.getBrowserForDocument(aDocument).currentURI.host" (above) fails?
        else
            for(var i=0; i<httpsfinder.results.whitelist.length; i++)
                if(i > httpsfinder.results.permWhitelistLength - 1 &&
                    httpsfinder.Overlay.getHostWithoutSub(httpsfinder.results.whitelist[i]) == httpsfinder.Overlay.getHostWithoutSub(host)){
                    if(httpsfinder.debug)
                        dump("3 httpsfinder removing " + httpsfinder.results.whitelist[i] + " from whitelist\n");
                    httpsfinder.results.whitelist.splice(i,1);
                }
    },

    //User clicked "Clear Session Whitelist" - Reset good and bad cached results, as well as user temporary whitelist.
    resetWhitelist: function(){
        httpsfinder.popupNotify("HTTPS Finder", httpsfinder.strings.getString("httpsfinder.overlay.whitelistReset"));

        //Fires re-import of whitelist through observer - Need to remove this since the whitelist is now in JSM (can call directly)
        httpsfinder.prefs.setBoolPref("whitelistChanged", true);

        httpsfinder.results.goodSSL.length = 0;
        httpsfinder.results.goodSSL = [];
        httpsfinder.results.whitelist.length = 0;
        httpsfinder.results.whitelist = [];
        httpsfinder.results.permWhitelistLength = 0;
    },

    //Preference observer
    observe: function(subject, topic, data){
        if (topic != "nsPref:changed")
            return;

        switch(data){
            //Reimport whitelist if user added or removed item
            case "whitelistChanged":
                httpsfinder.Overlay.importWhitelist();
                break;

            //Remove/add window listener if httpsfinder is enabled or disabled
            case "enable":
                if(!httpsfinder.prefs.getBoolPref("enable")){
                    try{
                        httpsfinder.Detect.unregister();
                    } catch(e){ /*do nothing - it is already removed if the extension was disabled*/ }

                    try{
                        var appcontent = document.getElementById("appcontent");
                        if(appcontent)
                            appcontent.removeEventListener("DOMContentLoaded", httpsfinder.Overlay.onPageLoadListener, true);
                    } catch(e){ /*appcontent may be null*/ }

                    gBrowser.tabContainer.removeEventListener("TabSelect", httpsfinder.Overlay.tabChangedListener, false);

                    var hs = hfCC["@mozilla.org/browser/nav-history-service;1"].
                    getService(hfCI.nsINavHistoryService);
                    hs.removeObserver(httpsfinder.history, "false");
        
                    httpsfinder.Cookies.unregister();
                }
                else if(httpsfinder.prefs.getBoolPref("enable"))
                    httpsfinder.Overlay.init();
                break;

            case "debugLogging":
                httpsfinder.debug = httpsfinder.prefs.getBoolPref("debugLogging");
                break;

            case "dismissAlerts":
                var container = gBrowser.tabContainer;

                if(httpsfinder.prefs.getBoolPref("dismissAlerts"))
                    container.addEventListener("TabSelect", httpsfinder.Overlay.tabChangedListener, false);
                else
                    container.removeEventListener("TabSelect", httpsfinder.Overlay.tabChangedListener, false);
                break;
        }
    },

    //Window is shutting down - remove listeners/observers
    shutdown: function(){
        try{
            httpsfinder.prefs.removeObserver("", this);
            httpsfinder.Detect.unregister();
        }
        catch(e){ /*do nothing - it is already removed if the extension was disabled*/ }

        try{
            var appcontent = document.getElementById("appcontent");
            if(appcontent)
                appcontent.removeEventListener("DOMContentLoaded", httpsfinder.Overlay.onPageLoadListener, true);
        }
        catch(e){ /*appcontent may be null*/ }


        var container = gBrowser.tabContainer;
        container.removeEventListener("TabSelect", httpsfinder.Overlay.tabChangedListener, false);

        var hs = hfCC["@mozilla.org/browser/nav-history-service;1"].
        getService(hfCI.nsINavHistoryService);
    
        try{
            hs.removeObserver(httpsfinder.history, "false");
        } catch(e) {/*may be null if enabled pref is false*/ }
        
        httpsfinder.Cookies.unregister();
        
        window.removeEventListener("unload", function(){
            httpsfinder.Overlay.shutdown();
        }, false);

        window.removeEventListener("load", function(){
            httpsfinder.Overlay.init();
        }, false);
    }
};

httpsfinder.history = {
    onBeginUpdateBatch: function() {},
    onEndUpdateBatch: function() {},
    onVisit: function(aURI, aVisitID, aTime, aSessionID, aReferringID, aTransitionType) {},
    onTitleChanged: function(aURI, aPageTitle) {},
    onBeforeDeleteURI: function(aURI) {},
    onPageChanged: function(aURI, aWhat, aValue) {},
    onDeleteVisits: function(aURI, aVisitTime, aGUID) {},

    /*
                *Called when user deletes all instances of a specific URI
                *(warning: Called for each URI in batch operations too)
                */
    onDeleteURI: function(aURI){
        let host = aURI.host;

        if(httpsfinder.results.goodSSL.indexOf(host) != -1)
            for(let i = 0; i < httpsfinder.results.goodSSL.length; i++){
                if(httpsfinder.results.goodSSL[i] == host){
                    httpsfinder.results.goodSSL.splice(i,1);
                    return;
                }
            }

        else if(httpsfinder.Overlay.isWhitelisted(host) && !httpsfinder.Overlay.isPermWhitelisted(host)){
            httpsfinder.Overlay.removeFromWhitelist(null, host);
        }
    },

    //Called when all history is cleared.
    onClearHistory: function() {
        httpsfinder.Overlay.resetWhitelist();
    },

    QueryInterface: XPCOMUtils.generateQI([hfCI.nsINavHistoryObserver])
};        



window.addEventListener("load", function(){
    httpsfinder.Overlay.init();
}, false);

window.addEventListener("unload", function(){
    httpsfinder.Overlay.shutdown();
}, false);