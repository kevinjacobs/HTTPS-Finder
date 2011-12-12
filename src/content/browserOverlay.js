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

if (!httpsfinder) var httpsfinder = {
    prefs: null, //prefs object for httpsfinder branch
    strings: null, //Strings object for httpsfinder strings
    history: null, //History observer object (clears results when history is cleared)
    debug: null, //verbose logging bool
    pbs: null//check private browsing status before saving detection results
};


//detect handles background detection and http observation
httpsfinder.detect = {
    //Not a great solution, but this is for problematic domains.
    //Google image search over ssl is one, so we won't cache results there.
    cacheExempt: ["www.google.com", "translate.google.com", "encrypted.google.com"],

    QueryInterface: function(aIID){
        if (aIID.equals(Components.interfaces.nsIObserver)
            || aIID.equals(Components.interfaces.nsISupports))
            return this;
        throw Components.results.NS_NOINTERFACE;
    },

    //Watches HTTP responses, filters and calls detection if needed
    observe: function(request,aTopic, aData){
        if (aTopic == "http-on-examine-response") {
            request.QueryInterface(Components.interfaces.nsIHttpChannel);
            if(!httpsfinder.prefs.getBoolPref("enable"))
                return;

            if((request.responseStatus == 200 || request.responseStatus == 301
                || request.responseStatus == 304) && request.URI.scheme == "http")
                var loadFlags = httpsfinder.detect.getStringArrayOfLoadFlags(request.loadFlags);
            else
                return;

            if(loadFlags.indexOf("LOAD_DOCUMENT_URI") != -1 && loadFlags.indexOf("LOAD_INITIAL_DOCUMENT_URI") != -1){
                if(httpsfinder.browserOverlay.isWhitelisted(request.URI.host.toLowerCase())){
                    if(httpsfinder.debug)
                        dump("Canceling detection on " + request.URI.host.toLowerCase() + ". Host is whitelisted\n");
                    return;
                }

                var browser = httpsfinder.detect.getBrowserFromChannel(request);
                if (browser == null){
                    if(httpsfinder.debug)
                        dump("httpsfinder browser cannot be found for channel\n");
                    return;
                }

                var host = request.URI.host.toLowerCase();
                try{
                    if(httpsfinder.detect.hostsMatch(browser.contentDocument.baseURIObject.host.toLowerCase(),host) &&
                        httpsfinder.results.goodSSL.indexOf(request.URI.host.toLowerCase()) != -1){
                        if(httpsfinder.debug)
                            dump("Canceling detection on " + request.URI.host.toLowerCase() + ". Good SSL already cached for host.\n");
                        httpsfinder.detect.handleCachedSSL(browser, request);
                        return;
                    }
                }catch(e){
                    if(e.name == 'NS_ERROR_FAILURE')
                        dump("HTTPS Finder: cannot match URI to browser request.\n");
                }

                //Push to whitelist so we don't spam with multiple detection requests - may be removed later depending on result
                if(!httpsfinder.browserOverlay.isWhitelisted(host) &&
                    !httpsfinder.pbs.privateBrowsingEnabled){
                    httpsfinder.results.whitelist.push(host);
                    if(httpsfinder.debug){
                        dump("httpsfinder Blocking detection on " + request.URI.host + " until OK response received\n");
                        dump("httpsfinder Starting HTTPS detection for " + request.URI.asciiSpec + "\n");
                    }
                }

                httpsfinder.detect.detectSSL(browser, request);
            }
        }
    },

    register: function() {
        var observerService = Components.classes["@mozilla.org/observer-service;1"]
        .getService(Components.interfaces.nsIObserverService);
        observerService.addObserver(httpsfinder.detect, "http-on-examine-response", false);
    },

    unregister: function() {
        var observerService = Components.classes["@mozilla.org/observer-service;1"]
        .getService(Components.interfaces.nsIObserverService);
        observerService.removeObserver(httpsfinder.detect, "http-on-examine-response");
    },

    hostsMatch: function(host1, host2){
        //check domain name of page location and detected host. Slice after first . to ignore subdomains
        if(host1.slice(host1.indexOf(".",0) + 1,host1.length) == host2.slice(host2.indexOf(".",0) + 1,host2.length))
            return true;
        else
            return false;
    },

    //HTTPS detection function - does HEAD falling back to GET, or just GET depending on user settings
    detectSSL: function(aBrowser, request){
        var requestURL = request.URI.asciiSpec.replace("http://", "https://");

        //If user preference specifies GET detection only
        if(!httpsfinder.prefs.getBoolPref("headfirst")){
            var getReq = new XMLHttpRequest();
            getReq.mozBackgroundRequest = true;
            getReq.open('GET', requestURL, true);            
            getReq.channel.loadFlags |= Components.interfaces.nsIRequest.LOAD_BYPASS_CACHE;
            getReq.onreadystatechange = function (aEvt) {
                if (getReq.readyState == 4){
                    httpsfinder.detect.handleDetectionResponse(aBrowser, getReq, requestURL);
                }
            };
            getReq.send(null);
        }
        else{ //Otherwise, try HEAD and fall back to GET if necessary (default bahavior)
            var headReq = new XMLHttpRequest();
            headReq.mozBackgroundRequest = true;
            headReq.open('HEAD', requestURL, true);
            headReq.channel.loadFlags |= Components.interfaces.nsIRequest.LOAD_BYPASS_CACHE;
            headReq.onreadystatechange = function (aEvt) {
                if (headReq.readyState == 4){
                    if(headReq.status == 200 || headReq.status == 0 ||
                        (headReq.status != 405 && headReq.status != 403))
                        httpsfinder.detect.handleDetectionResponse(aBrowser, headReq, requestURL);
                    else if(headReq.status == 405 || headReq.status == 403){
                        dump("httpsfinder detection falling back to GET for " + requestURL + "\n");
                        var getReq = new XMLHttpRequest();
                        getReq.mozBackgroundRequest = true;
                        getReq.open('GET', requestURL, true);
                        getReq.channel.loadFlags |= Components.interfaces.nsIRequest.LOAD_BYPASS_CACHE;
                        getReq.onreadystatechange = function (aEvt) {
                            if (getReq.readyState == 4)
                                httpsfinder.detect.handleDetectionResponse(aBrowser, getReq, requestURL);
                        };
                        getReq.send(null);
                    }
                }
            };
            headReq.send(null);
        }
    },

    //Get load flags for HTTP observer. We use these to filter normal http requests from page load requests
    getStringArrayOfLoadFlags : function(flags) {
        var flagsArr = [];

        //Look for the two load flags that indicate a page load (ignore others)
        if (flags & Components.interfaces.nsIChannel.LOAD_DOCUMENT_URI)
            flagsArr.push("LOAD_DOCUMENT_URI");
        if (flags & Components.interfaces.nsIChannel.LOAD_INITIAL_DOCUMENT_URI)
            flagsArr.push("LOAD_INITIAL_DOCUMENT_URI");

        return flagsArr;
    },

    //Used by HTTP observer to match requests to tabs
    getBrowserFromChannel: function (aChannel) {
        try {
            var notificationCallbacks = aChannel.notificationCallbacks ? aChannel.notificationCallbacks : aChannel.loadGroup.notificationCallbacks;
            if (!notificationCallbacks)
                return null;
            var domWin = notificationCallbacks.getInterface(Components.interfaces.nsIDOMWindow);
            return gBrowser.getBrowserForDocument(domWin.top.document);
        }
        catch (e) {
            return null;
        }
    },

    //If good SSL has alread been found during this session, skip new detection and use this function
    handleCachedSSL: function(aBrowser, request){
        if(request.responseStatus != 200 && request.responseStatus != 301 && request.responseStatus != 302)
            return;

        var nb = gBrowser.getNotificationBox(aBrowser);
        var sslFoundButtons = [{
            label: httpsfinder.strings.getString("httpsfinder.main.whitelist"),
            accessKey: httpsfinder.strings.getString("httpsfinder.main.whitelistKey"),
            popup: null,
            callback: httpsfinder.browserOverlay.whitelistDomain
        },{
            label: httpsfinder.strings.getString("httpsfinder.main.noRedirect"),
            accessKey: httpsfinder.strings.getString("httpsfinder.main.noRedirectKey"),
            popup: null,
            callback: httpsfinder.browserOverlay.redirectNotNow
        },{
            label: httpsfinder.strings.getString("httpsfinder.main.yesRedirect"),
            accessKey: httpsfinder.strings.getString("httpsfinder.main.yesRedirectKey"),
            popup: null,
            callback: httpsfinder.browserOverlay.redirect
        }];


        if(httpsfinder.prefs.getBoolPref("autoforward"))
            httpsfinder.browserOverlay.redirectAuto(aBrowser, request);
        else if(httpsfinder.results.tempNoAlerts.indexOf(request.URI.host) == -1 &&
            httpsfinder.prefs.getBoolPref("httpsfoundalert")){

            nb.appendNotification(httpsfinder.strings.getString("httpsfinder.main.httpsFoundPrompt"),
                "httpsfinder-https-found",'chrome://httpsfinder/skin/httpsAvailable.png',
                nb.PRIORITY_INFO_HIGH, sslFoundButtons);

            if(httpsfinder.prefs.getBoolPref("dismissAlerts"))
                setTimeout(function(){
                    httpsfinder.removeNotification("httpsfinder-https-found")
                },httpsfinder.prefs.getIntPref("alertDismissTime") * 1000, 'httpsfinder-https-found');
        }
    },

    //Callback function for our HTTPS detection request
    handleDetectionResponse: function(aBrowser, sslTest){
        //Session whitelist host and return if cert is bad or status is not OK.
        var host = sslTest.channel.URI.host.toLowerCase();
        var request = sslTest.channel;

        var cacheExempt = (httpsfinder.detect.cacheExempt.indexOf(host) != -1) ? true : false;

        if(cacheExempt){
            if(httpsfinder.debug)
                dump("httpsfinder removing " + host + " from whitelist (exempt from saving results on this host)\n");
            httpsfinder.browserOverlay.removeFromWhitelist(null, aBrowser.contentDocument.baseURIObject.host.toLowerCase());
        }

        var Codes = [200, 301, 302, 0];

        if(Codes.indexOf(sslTest.status) == -1 && httpsfinder.results.goodSSL.indexOf(host) == -1){
            if(httpsfinder.debug)
                dump("httpsfinder leaving " + host + " in whitelist (return status code " + sslTest.status + ")\n");
            return;
        }
        else if(sslTest.status == 0 && !httpsfinder.detect.testCertificate(request,sslTest.status, aBrowser) && httpsfinder.results.goodSSL.indexOf(host) == -1){
            if(httpsfinder.debug)
                dump("httpsfinder leaving " + host + " in whitelist (bad SSL certificate)\n");
            return;
        }
        else if(!httpsfinder.detect.testCertificate(request, null, null) && httpsfinder.results.goodSSL.indexOf(host) == -1){
            if(httpsfinder.debug)
                dump("httpsfinder leaving " + host + " in whitelist (bad SSL certificate)\n");
            return;
        }
        else
            httpsfinder.browserOverlay.removeFromWhitelist(null, host);          
          
        //If the code gets to this point, the HTTPS is good.
        
        //Push host to good SSL list (remember result and skip repeat detection)
        if(httpsfinder.results.goodSSL.indexOf(host) == -1 && !httpsfinder.pbs.privateBrowsingEnabled){
            if(httpsfinder.debug) dump("Pushing " + host + " to good SSL list\n");

            httpsfinder.browserOverlay.removeFromWhitelist(null,host);
            if(!cacheExempt)
                httpsfinder.results.goodSSL.push(host);
        }
        else if(!httpsfinder.results.goodSSL.indexOf(aBrowser.contentDocument.baseURIObject.host.toLowerCase()) == -1
            && !httpsfinder.pbs.privateBrowsingEnabled){
            var altHost = aBrowser.contentDocument.baseURIObject.host.toLowerCase();
            if(httpsfinder.debug) dump("Pushing " + altHost + " to good SSL list.\n");

            httpsfinder.browserOverlay.removeFromWhitelist(null,altHost);
            if(!cacheExempt)
                httpsfinder.results.goodSSL.push(altHost);
        }

        //Check setting and automatically enforce HTTPS
        if(httpsfinder.prefs.getBoolPref("autoforward"))
            httpsfinder.browserOverlay.redirectAuto(aBrowser, request);

        //If auto-enforce is disabled, if host is not in tempNoAlerts (rule already saved)
        //and HTTPS Found alerts are enabled, alert user of good HTTPS
        else  if(httpsfinder.results.tempNoAlerts.indexOf(request.URI.host) == -1 &&
            httpsfinder.prefs.getBoolPref("httpsfoundalert")){
            if(httpsfinder.detect.hostsMatch(aBrowser.contentDocument.baseURIObject.host.toLowerCase(),host)){

                var nb = gBrowser.getNotificationBox(aBrowser);
                var sslFoundButtons = [{
                    label: httpsfinder.strings.getString("httpsfinder.main.whitelist"),
                    accessKey: httpsfinder.strings.getString("httpsfinder.main.whitelistKey"),
                    popup: null,
                    callback: httpsfinder.browserOverlay.whitelistDomain
                },{
                    label: httpsfinder.strings.getString("httpsfinder.main.noRedirect"),
                    accessKey: httpsfinder.strings.getString("httpsfinder.main.noRedirectKey"),
                    popup: null,
                    callback: httpsfinder.browserOverlay.redirectNotNow
                },{
                    label: httpsfinder.strings.getString("httpsfinder.main.yesRedirect"),
                    accessKey: httpsfinder.strings.getString("httpsfinder.main.yesRedirectKey"),
                    popup: null,
                    callback: httpsfinder.browserOverlay.redirect
                }];

                nb.appendNotification(httpsfinder.strings.getString("httpsfinder.main.httpsFoundPrompt"),
                    "httpsfinder-https-found",'chrome://httpsfinder/skin/httpsAvailable.png',
                    nb.PRIORITY_INFO_HIGH, sslFoundButtons);
                httpsfinder.browserOverlay.removeFromWhitelist(aBrowser.contentDocument, null);

                if(httpsfinder.prefs.getBoolPref("dismissAlerts"))
                    setTimeout(function(){
                        httpsfinder.removeNotification("httpsfinder-https-found")
                    },httpsfinder.prefs.getIntPref("alertDismissTime") * 1000, 'httpsfinder-https-found');
            }
            else{
                //Catches certain browser location changes and page content that had load flags to fire detection
                if(httpsfinder.debug)
                    dump("Host mismatch, alert blocked (Document: " +
                        aBrowser.contentDocument.baseURIObject.host.toLowerCase() + " , Detection host: " + host + "\n");
            }
        }
    },

    //Certificate testing done before alerting user of https presence
    testCertificate: function(channel, status, aBrowser) {
        var secure = false;
        try {
            const Ci = Components.interfaces;
            if (! channel instanceof  Ci.nsIChannel){
                if(httpsfinder.debug)
                    dump("httpsfinder testCertificate: Invalid channel object\n");
                return false;
            }

            var secInfo = channel.securityInfo;
            if (secInfo instanceof Ci.nsITransportSecurityInfo) {
                secInfo.QueryInterface(Ci.nsITransportSecurityInfo);
                // Check security state flags
                if ((secInfo.securityState & Ci.nsIWebProgressListener.STATE_IS_SECURE) ==
                    Ci.nsIWebProgressListener.STATE_IS_SECURE)
                    secure = true;
            }
            //Check SSL certificate details
            if (secInfo instanceof Ci.nsISSLStatusProvider) {
                var cert = secInfo.QueryInterface(Ci.nsISSLStatusProvider).
                SSLStatus.QueryInterface(Ci.nsISSLStatus).serverCert;
                var verificationResult = cert.verifyForUsage(Ci.nsIX509Cert.CERT_USAGE_SSLServer);
               
                switch (verificationResult) {
                    case Ci.nsIX509Cert.VERIFIED_OK:
                        if(status != 0)
                             secure = true;                       
                        break;
                    case Ci.nsIX509Cert.NOT_VERIFIED_UNKNOWN:
                        secure = false;
                        break;
                    case Ci.nsIX509Cert.CERT_REVOKED:
                        secure = false;
                        break;
                    case Ci.nsIX509Cert.CERT_EXPIRED:
                        secure = false;
                        break;
                    case Ci.nsIX509Cert.CERT_NOT_TRUSTED:
                        secure = false;
                        break;
                    case Ci.nsIX509Cert.ISSUER_NOT_TRUSTED:
                        if(httpsfinder.prefs.getBoolPref("allowSelfSignedCerts")){
                            
                            var nb = gBrowser.getNotificationBox(aBrowser);
                            
                            var wlButton = [{
                                label: httpsfinder.strings.getString("httpsfinder.main.whitelist"),
                                accessKey: httpsfinder.strings.getString("httpsfinder.main.whitelistKey"),
                                popup: null,
                                callback: httpsfinder.browserOverlay.whitelistDomain
                            },{
                                label: httpsfinder.strings.getString("httpsfinder.main.yesRedirect"),
                                accessKey: httpsfinder.strings.getString("httpsfinder.main.yesRedirectKey"),
                                popup: null,
                                callback: httpsfinder.browserOverlay.redirect
                            }];

                            nb.appendNotification(httpsfinder.strings.getString("httpsfinder.main.selfSignedAlert"),
                                "httpsfinder-ssl-selfSigned", 'chrome://httpsfinder/skin/httpsAvailable.png',
                                nb.PRIORITY_INFO_HIGH, wlButton);
                            if(httpsfinder.prefs.getBoolPref("dismissAlerts"))
                                setTimeout(function(){
                                    httpsfinder.removeNotification("httpsfinder-ssl-selfSigned")
                                },httpsfinder.prefs.getIntPref("alertDismissTime") * 1000, 'httpsfinder-ssl-selfSigned');
                        }
                        secure = false;                                
                        break;
                    case Ci.nsIX509Cert.ISSUER_UNKNOWN:
                        secure = false;
                        break;
                    case Ci.nsIX509Cert.INVALID_CA:
                        secure = false;
                        break;
                    default:
                        secure = false;
                        break;
                }       
            }
        }
        catch(err){
            secure = false;
            Components.utils.reportError("HTTPS Finder: testCertificate error: " + err.toString() + "\n");
        } 
        if(httpsfinder.debug && secure)
            dump("httpsfinder testCertificate: cert OK (on "+
                channel.URI.host.toLowerCase()+ ")\n");         
        return secure;
    }
};

//browserOverlay handles most 'browser' code (including alerts except those generated from detection, importing whitelist, startup/shutdown, etc)
httpsfinder.browserOverlay = {
    redirectedTab: [[]], //Tab info for pre-redirect URLs.
    recent: [[]], //Recent auto-redirects used for detecting http->https->http redirect loops. Second subscript holds the tabIndex of the redirect
    lastRecentReset: null, //time counter for detecting redirect loops

    //Window start up - set listeners, read in whitelist, etc
    init: function(){
        Components.utils.import("resource://hfShared/hfShared.js", httpsfinder);

        var prefs = Components.classes["@mozilla.org/preferences-service;1"]
        .getService(Components.interfaces.nsIPrefBranch);
        httpsfinder.prefs =  prefs.getBranch("extensions.httpsfinder.");

        if(!httpsfinder.prefs.getBoolPref("enable"))
            return;

        //pref change observer
        httpsfinder.prefs.QueryInterface(Components.interfaces.nsIPrefBranch2);
        httpsfinder.prefs.addObserver("", this, false);

        //History observer
        var hs = Components.classes["@mozilla.org/browser/nav-history-service;1"].
        getService(Components.interfaces.nsINavHistoryService);

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

                else if(httpsfinder.browserOverlay.isWhitelisted(host) && !httpsfinder.browserOverlay.isPermWhitelisted(host)){
                    httpsfinder.browserOverlay.removeFromWhitelist(null, host);
                }
            },

            //Called when all history is cleared.
            onClearHistory: function() {
                httpsfinder.browserOverlay.resetWhitelist();
            },

            QueryInterface: XPCOMUtils.generateQI([Components.interfaces.nsINavHistoryObserver])
        };        

        hs.addObserver(httpsfinder.history, false);

        //Used for auto-dismissing alerts (auto-dismiss timer is started when user clicks on a tab, so they don't miss background alerts)
        var container = gBrowser.tabContainer;
        container.addEventListener("TabSelect", httpsfinder.browserOverlay.tabChangedListener, false);

        //Listener is used for displaying HTTPS alerts after a page is loaded
        var appcontent = document.getElementById("appcontent");
        if(appcontent)
            appcontent.addEventListener("load", httpsfinder.browserOverlay.onPageLoadListener, true);

        //Used to check private browsing status before caching detection results
        httpsfinder.pbs = Components.classes["@mozilla.org/privatebrowsing;1"]
        .getService(Components.interfaces.nsIPrivateBrowsingService);

        //Register HTTP observer for HTTPS detection
        httpsfinder.detect.register();

        httpsfinder.strings = document.getElementById("httpsfinderStrings");
        if(httpsfinder.prefs == null || httpsfinder.strings == null){
            dump("httpsfinder cannot load preferences or strings - init() failed\n");
            return;
        }
         
        var installedVersion = httpsfinder.prefs.getCharPref("version");
        var firstrun = httpsfinder.prefs.getBoolPref("firstrun");
        httpsfinder.debug = httpsfinder.prefs.getBoolPref("debugLogging");

        //Try/catch attempts to recreate db table (in case it has been deleted). Doesn't overwrite though
        try{
            //Create whitelist database
            var file = Components.classes["@mozilla.org/file/directory_service;1"]
            .getService(Components.interfaces.nsIProperties)
            .get("ProfD", Components.interfaces.nsIFile);
            file.append("httpsfinder.sqlite");
            var storageService = Components.classes["@mozilla.org/storage/service;1"]
            .getService(Components.interfaces.mozIStorageService);
            var mDBConn = storageService.openDatabase(file); //Creates db on first run.
            mDBConn.createTable("whitelist", "rule STRING NOT NULL UNIQUE");

        }catch(e){
            //NS_ERROR_FAILURE is thrown when we try to recreate a table (May be too generic though...))
            if(e.name != 'NS_ERROR_FAILURE')
                Components.utils.reportError("HTTPS Finder: initialize error " + e + "\n");
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
                httpsfinder.browserOverlay.importWhitelist();
            }
            else //All other startup
                httpsfinder.browserOverlay.importWhitelist();
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
    * onPageLoadListener checks for any HTTPS redirect/detection activity for the tab. If there is something that the user needs to be alerted of,
    * The notification is added. We can't add the notification directly from the detection callback, because page content still being loaded
    * causes the notifications to be automatically dismissed from time to time. This is basically a method to slow down alerts until the page is ready.
    */
    onPageLoadListener: function(aEvent) {
        var brow = gBrowser.getBrowserForDocument(aEvent.originalTarget);
        var index = gBrowser.getBrowserIndexForDocument(aEvent.originalTarget);
        if(typeof httpsfinder.browserOverlay.redirectedTab[index] == "undefined" ||
            typeof httpsfinder.browserOverlay.redirectedTab[index][0] == "undefined" ||
            typeof httpsfinder.browserOverlay.redirectedTab[index][1] == "undefined" ||
            brow.currentURI.scheme != "https" || brow == null)
            return;

        var tabHost = brow.currentURI.host;
        var storedHost = httpsfinder.browserOverlay.redirectedTab[index][1].host;
        if(httpsfinder.browserOverlay.getHostWithoutSub(tabHost) != httpsfinder.browserOverlay.getHostWithoutSub(storedHost)){
            //Alert was for a previous tab and was not dismissed (page change timed just right before alert was cleared
            httpsfinder.browserOverlay.redirectedTab[index] = new Array();
            if(httpsfinder.debug)
                dump("httpsfinder resetting alert for tab - host mismatch on " + tabHost  +  " and "  + storedHost + "\n");
            return;
        }

        //If user was redirected - Redirected array holds at [x][0] a bool for whether or not the tab index has been redirected.
        //[x][1] holds a string hostname for the pre-redirect URL.  This is necessary because some sites like Google redirect to
        //encrypted.google.com when you use HTTPS.  We have to remember the old URL so it can be whitelisted from the alert drop down.
        if(httpsfinder.browserOverlay.redirectedTab[index][0]){
            if(!httpsfinder.prefs.getBoolPref("noruleprompt"))
                httpsfinder.browserOverlay.alertSSLEnforced(aEvent.originalTarget);
            httpsfinder.browserOverlay.redirectedTab[index][0] = false;
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
            var file = Components.classes["@mozilla.org/file/directory_service;1"]
            .getService(Components.interfaces.nsIProperties)
            .get("ProfD", Components.interfaces.nsIFile);
            file.append("httpsfinder.sqlite");
            var storageService = Components.classes["@mozilla.org/storage/service;1"]
            .getService(Components.interfaces.mozIStorageService);
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

                    if (aReason != Components.interfaces.mozIStorageStatementCallback.REASON_FINISHED)
                        dump("httpsfinder database error " + aReason.message + "\n");
                    else if(httpsfinder.prefs.getBoolPref("whitelistChanged"))
                        httpsfinder.prefs.setBoolPref("whitelistChanged", false);
                }
            });
        }
        catch(e){
            Components.utils.reportError("HTTPS Finder: load whitelist " + e.name + "\n");
        }
        finally{
            statement.reset();
            mDBConn.asyncClose()
        }
    },

    //User clicked "Add to whitelist" from a drop down notification. Save to sqlite and whitelist array.
    whitelistDomain: function(hostIn){
        //Manually remove notification - in Ubuntu it stays up (no error is thrown)
        httpsfinder.removeNotification('httpsfinder-https-found');
        httpsfinder.removeNotification('httpsfinder-ssl-enforced');

        //If no host was passed, get it manually from stored values.
        if(typeof(hostIn) != "string"){
            var hostname;
            if(typeof httpsfinder.browserOverlay.redirectedTab[gBrowser.getBrowserIndexForDocument(gBrowser.contentDocument)] != "undefined" &&
                typeof httpsfinder.browserOverlay.redirectedTab[gBrowser.getBrowserIndexForDocument(gBrowser.contentDocument)][1] != "undefined" )
                hostname = httpsfinder.browserOverlay.redirectedTab[gBrowser.getBrowserIndexForDocument(gBrowser.contentDocument)][1].host.toLowerCase();
            else
                hostname = gBrowser.currentURI.host.toLowerCase();

            //Bug workaround.  If user closes tab in the middle of open tabs, the indexes are shifted.  The only time we can't just use currentURI
            //is when the https:// page forwards to a subdomain.  This is rare.  With the for loop below, this bug can still happen, but only under the following conditions:
            //1) Auto forward enabled. 2)User browsed to a site where HTTPS forwards to a different hostname 3)conditions 1 and 2 are done in a background tab
            //4) Some tab before the above tab is closed, then user switches to the target tab and clicks "Add to whitelist".  This is unlikely enough that I'm leaving
            //it in for now.  Will look for a better way to do this than the redirectedTab array.
            for(var i=0; i<httpsfinder.browserOverlay.redirectedTab.length; i++){
                if(typeof httpsfinder.browserOverlay.redirectedTab[i] == "undefined" || typeof httpsfinder.browserOverlay.redirectedTab[i][1] == "undefined")
                    hostname = hostname; //do nothing
                else if(httpsfinder.browserOverlay.redirectedTab[i][1].host.toLowerCase() == gBrowser.currentURI.host.toLowerCase())
                    hostname = gBrowser.currentURI.host.toLowerCase();
            }
        }
        else if(typeof(hostIn) == "string")
            hostname = hostIn;

        try{
            var file = Components.classes["@mozilla.org/file/directory_service;1"]
            .getService(Components.interfaces.nsIProperties)
            .get("ProfD", Components.interfaces.nsIFile);
            file.append("httpsfinder.sqlite");
            var storageService = Components.classes["@mozilla.org/storage/service;1"]
            .getService(Components.interfaces.mozIStorageService);
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
                    if (aReason == Components.interfaces.mozIStorageStatementCallback.REASON_FINISHED)
                        if(!httpsfinder.browserOverlay.isWhitelisted(hostname) &&
                            !httpsfinder.pbs.privateBrowsingEnabled){
                            httpsfinder.results.whitelist.push(hostname);
                        }
                }
            });
        }
        catch(e){
            Components.utils.reportError("HTTPS Finder: addToWhitelist " + e.name + "\n");
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
                callback: httpsfinder.browserOverlay.whitelistDomain
            },{
                label: httpsfinder.strings.getString("httpsfinder.main.noThanks"),
                accessKey: httpsfinder.strings.getString("httpsfinder.main.noThanksKey"),
                popup: null,
                callback: httpsfinder.browserOverlay.redirectNotNow
            },{
                label: httpsfinder.strings.getString("httpsfinder.main.rememberSetting"),
                accessKey: httpsfinder.strings.getString("httpsfinder.main.rememberSettingKey"),
                popup: null,
                callback: httpsfinder.browserOverlay.writeRule
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
        var eTLDService = Components.classes["@mozilla.org/network/effective-tld-service;1"]
        .getService(Components.interfaces.nsIEffectiveTLDService);

        var topLevel = null;
        try{
            //Try retrieving the pre-redirect host from the redirected array
            topLevel = "." + eTLDService.getPublicSuffix(httpsfinder.browserOverlay.redirectedTab[gBrowser.getBrowserIndexForDocument(gBrowser.contentDocument)][1]);
            var hostname = httpsfinder.browserOverlay.redirectedTab[gBrowser.getBrowserIndexForDocument(gBrowser.contentDocument)][1].host.toLowerCase();
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
        if(typeof httpsfinder.browserOverlay.redirectedTab[gBrowser.getBrowserIndexForDocument(gBrowser.contentDocument)] != "undefined" &&
            typeof httpsfinder.browserOverlay.redirectedTab[gBrowser.getBrowserIndexForDocument(gBrowser.contentDocument)][1] != "undefined" )
            hostname = httpsfinder.browserOverlay.redirectedTab[gBrowser.getBrowserIndexForDocument(gBrowser.contentDocument)][1].host.toLowerCase();
        else
            hostname = gBrowser.currentURI.host.toLowerCase();

        //Bug workaround.  If user closes tab in the middle of open tabs, the indexes are shifted.  The only time we can't just use currentURI
        //is when the https:// page forwards to a subdomain.  This is rare.  With the for loop below, this bug can still happen, but only under the following conditions:
        //1) Auto forward enabled. 2)User browsed to a site where HTTPS forwards to a different hostname 3)conditions 1 and 2 are done in a background tab
        //4) Some tab before the above tab is closed, then user switches to the target tab and clicks "Add to whitelist".  This is unlikely enough that I'm leaving
        //it in for now.  Will look for a better way to do this than the redirectedTab array.
        for(var i=0; i<httpsfinder.browserOverlay.redirectedTab.length; i++){
            if(typeof httpsfinder.browserOverlay.redirectedTab[i] == "undefined" ||
                typeof httpsfinder.browserOverlay.redirectedTab[i][1] == "undefined")
                hostname = hostname; //do nothing
            else if(httpsfinder.browserOverlay.redirectedTab[i][1].host.toLowerCase() ==
                gBrowser.currentURI.host.toLowerCase())
                hostname = gBrowser.currentURI.host.toLowerCase();
        }
        if(!httpsfinder.browserOverlay.isWhitelisted(hostname) && !httpsfinder.pbs.privateBrowsingEnabled)
            httpsfinder.results.whitelist.push(hostname);
    },

    //Auto-redirect to https
    redirectAuto: function(aBrowser, request){
        var sinceLastReset = Date.now() - httpsfinder.browserOverlay.lastRecentReset;
        var index = gBrowser.getBrowserIndexForDocument(aBrowser.contentDocument);
        var requestURL = request.URI.asciiSpec.replace("http://", "https://");
        var host = request.URI.host.toLowerCase();

        var redirectLoop = false;
        ///Need to determine if link was clicked, or if reload is automatic
        if(sinceLastReset < 2500 && sinceLastReset > 200){
            for(var i=0; i<httpsfinder.browserOverlay.recent.length; i++){
                if(httpsfinder.browserOverlay.recent[i][0] == host && httpsfinder.browserOverlay.recent[i][1] == index){
                    if(!httpsfinder.browserOverlay.isWhitelisted(host) &&
                        !httpsfinder.pbs.privateBrowsingEnabled)
                        httpsfinder.results.whitelist.push(host);

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
            httpsfinder.browserOverlay.recent.length = 0;
        }

        if(httpsfinder.detect.hostsMatch(aBrowser.contentDocument.baseURIObject.host.toLowerCase(),host) && !redirectLoop){
            aBrowser.loadURIWithFlags(requestURL, nsIWebNavigation.LOAD_FLAGS_REPLACE_HISTORY);
            httpsfinder.browserOverlay.redirectedTab[index] = new Array();
            httpsfinder.browserOverlay.redirectedTab[index][0] = true;
            httpsfinder.browserOverlay.redirectedTab[index][1] = aBrowser.currentURI;

            httpsfinder.browserOverlay.removeFromWhitelist(aBrowser.contentDocument, request.URI.host.toLowerCase());
        }
        else{
            if(httpsfinder.debug && !redirectLoop)
                dump("Host mismatch, forward blocked (Document: " +
                    aBrowser.contentDocument.baseURIObject.host.toLowerCase() +
                    " , Detection host: " + host + "\n");
        }

        httpsfinder.browserOverlay.recent.push([host,index]);
        httpsfinder.browserOverlay.lastRecentReset = Date.now();
    },

    //Manual redirect (user clicked "Yes, go HTTPS")
    redirect: function() {
        var aDocument = gBrowser.contentDocument;
        httpsfinder.browserOverlay.redirectedTab[gBrowser.getBrowserIndexForDocument(aDocument)] = new Array();
        httpsfinder.browserOverlay.redirectedTab[gBrowser.getBrowserIndexForDocument(aDocument)][0] = true;

        var ioService = Components.classes["@mozilla.org/network/io-service;1"]
        .getService(Components.interfaces.nsIIOService);

        var uri = gBrowser.getBrowserForDocument(aDocument).currentURI.asciiSpec;
        uri = uri.replace("http://", "https://");

        httpsfinder.browserOverlay.redirectedTab[gBrowser.getBrowserIndexForDocument(aDocument)][1] = ioService.newURI(uri, null, null);
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
                    httpsfinder.browserOverlay.getHostWithoutSub(httpsfinder.results.whitelist[i]) == httpsfinder.browserOverlay.getHostWithoutSub(host)){
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
                httpsfinder.browserOverlay.importWhitelist();
                break;

            //Remove/add window listener if httpsfinder is enabled or disabled
            case "enable":
                var appcontent = document.getElementById("appcontent");
                if(!httpsfinder.prefs.getBoolPref("enable")){
                    window.removeEventListener("load", function() {
                        httpsfinder.browserOverlay.init();
                    }, false);
                    httpsfinder.detect.unregister();
                    if(appcontent)
                        appcontent.removeEventListener("DOMContentLoaded", httpsfinder.browserOverlay.onPageLoadListener, true);
                }
                else if(httpsfinder.prefs.getBoolPref("enable"))
                    httpsfinder.browserOverlay.init();
                break;

            case "debugLogging":
                httpsfinder.debug = httpsfinder.prefs.getBoolPref("debugLogging");
                break;

            case "dismissAlerts":
                var container = gBrowser.tabContainer;

                if(httpsfinder.prefs.getBoolPref("dismissAlerts"))
                    container.addEventListener("TabSelect", httpsfinder.browserOverlay.tabChangedListener, false);
                else
                    container.removeEventListener("TabSelect", httpsfinder.browserOverlay.tabChangedListener, false);
                break;
        }
    },

    //Window is shutting down - remove listeners/observers
    shutdown: function(){
        try{
            httpsfinder.prefs.removeObserver("", this);
            httpsfinder.detect.unregister();
        }
        catch(e){ /*do nothing - it is already removed if the extension was disabled*/ }

        try{
            var appcontent = document.getElementById("appcontent");
            if(appcontent)
                appcontent.removeEventListener("DOMContentLoaded", httpsfinder.browserOverlay.onPageLoadListener, true);
        }
        catch(e){ /*appcontent may be null*/ }

        window.removeEventListener("unload", function(){
            httpsfinder.browserOverlay.shutdown();
        }, false);

        window.removeEventListener("load", function(){
            httpsfinder.browserOverlay.init();
        }, false);

        var container = gBrowser.tabContainer;
        container.removeEventListener("TabSelect", httpsfinder.browserOverlay.tabChangedListener, false);

        var hs = Components.classes["@mozilla.org/browser/nav-history-service;1"].
        getService(Components.interfaces.nsINavHistoryService);
        hs.removeObserver(httpsfinder.history, "false");
    }
};

window.addEventListener("load", function(){
    httpsfinder.browserOverlay.init();
}, false);

window.addEventListener("unload", function(){
    httpsfinder.browserOverlay.shutdown();
}, false);