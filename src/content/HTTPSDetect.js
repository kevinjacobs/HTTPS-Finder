/*
 * HTTPSDetect.js handles background Detection and http observation
 */

httpsfinder.Cookies = {};
httpsfinder_INCLUDE('Cookies', httpsfinder.Cookies);
    
var OS = hfCC["@mozilla.org/observer-service;1"]
.getService(hfCI.nsIObserverService);


////Not a great solution, but this is for problematic domains.
//Google image search over ssl is one, so we won't cache results there.
var cacheExempt = ["www.google.com", "translate.google.com", "encrypted.google.com"];

function QueryInterface (aIID){
    if (aIID.equals(hfCI.nsIObserver) || aIID.equals(hfCI.nsISupports))
        return this;
    throw hfCR.NS_NOINTERFACE;
}

//Watches HTTP responses, filters and calls Detection if needed
function observe (request,aTopic, aData){
    if (aTopic == "http-on-examine-response") {
        request.QueryInterface(hfCI.nsIHttpChannel);
        if(!httpsfinder.prefs.getBoolPref("enable"))
            return;

        if((request.responseStatus == 200 || request.responseStatus == 301
            || request.responseStatus == 304) && request.URI.scheme == "http")
            var loadFlags = httpsfinder.Detect.getStringArrayOfLoadFlags(request.loadFlags);
        else
            return;

        if(loadFlags.indexOf("LOAD_DOCUMENT_URI") != -1 && loadFlags.indexOf("LOAD_INITIAL_DOCUMENT_URI") != -1){
            if(httpsfinder.Overlay.isWhitelisted(request.URI.host.toLowerCase())){
                if(httpsfinder.debug)
                    dump("Canceling Detection on " + request.URI.host.toLowerCase() + ". Host is whitelisted\n");
                return;
            }

            var browser = httpsfinder.Detect.getBrowserFromChannel(request);
            if (browser == null){
                if(httpsfinder.debug)
                    dump("httpsfinder browser cannot be found for channel\n");
                return;
            }

            var host = request.URI.host.toLowerCase();
            try{
                if(httpsfinder.Detect.hostsMatch(browser.contentDocument.baseURIObject.host.toLowerCase(),host) &&
                    httpsfinder.results.goodSSL.indexOf(request.URI.host.toLowerCase()) != -1){
                    if(httpsfinder.debug)
                        dump("Canceling Detection on " + request.URI.host.toLowerCase() + ". Good SSL already cached for host.\n");
                    httpsfinder.Detect.handleCachedSSL(browser, request);
                    return;
                }
            }catch(e){
                if(e.name == 'NS_ERROR_FAILURE')
                    dump("HTTPS Finder: cannot match URI to browser request.\n");
            }

            //Push to whitelist so we don't spam with multiple Detection requests - may be removed later depending on result
            if(!httpsfinder.Overlay.isWhitelisted(host) &&
                !httpsfinder.pbs.privateBrowsingEnabled){
                httpsfinder.results.whitelist.push(host);
                if(httpsfinder.debug){
                    dump("httpsfinder Blocking Detection on " + request.URI.host + " until OK response received\n");
                    dump("httpsfinder Starting HTTPS Detection for " + request.URI.asciiSpec + "\n");
                }
            }

            httpsfinder.Detect.detectSSL(browser, request);
        }
    }
}

function register() {
    OS.addObserver(httpsfinder.Detect, "http-on-examine-response", false);
}

function unregister () {
    try{    
        OS.removeObserver(httpsfinder.Detect, "http-on-examine-response");
    }
    catch(e) {/* already removed if enabled pref is false */}
}

function hostsMatch (host1, host2){
    //check domain name of page location and detected host. Slice after first . to ignore subdomains
    if(host1.slice(host1.indexOf(".",0) + 1,host1.length) == host2.slice(host2.indexOf(".",0) + 1,host2.length))
        return true;
    else
        return false;
}

//HTTPS Detection function - does HEAD falling back to GET, or just GET depending on user settings
function detectSSL (aBrowser, request){
    var requestURL = request.URI.asciiSpec.replace("http://", "https://");

    //If user preference specifies GET Detection only
    if(!httpsfinder.prefs.getBoolPref("headfirst")){
        var getReq = new XMLHttpRequest();
        getReq.mozBackgroundRequest = true;
        getReq.open('GET', requestURL, true);            
        getReq.channel.loadFlags |= hfCI.nsIRequest.LOAD_BYPASS_CACHE;
        getReq.onreadystatechange = function (aEvt) {
            if (getReq.readyState == 4){
                httpsfinder.Detect.handleDetectionResponse(aBrowser, getReq, requestURL);
            }
        };
        getReq.send(null);
    }
    else{ //Otherwise, try HEAD and fall back to GET if necessary (default bahavior)
        var headReq = new XMLHttpRequest();
        headReq.mozBackgroundRequest = true;
        headReq.open('HEAD', requestURL, true);
        headReq.channel.loadFlags |= hfCI.nsIRequest.LOAD_BYPASS_CACHE;
        headReq.onreadystatechange = function (aEvt) {
            if (headReq.readyState == 4){
                if(headReq.status == 200 || headReq.status == 0 ||
                    (headReq.status != 405 && headReq.status != 403))
                    httpsfinder.Detect.handleDetectionResponse(aBrowser, headReq, requestURL);
                else if(headReq.status == 405 || headReq.status == 403){
                    dump("httpsfinder Detection falling back to GET for " + requestURL + "\n");
                    var getReq = new XMLHttpRequest();
                    getReq.mozBackgroundRequest = true;
                    getReq.open('GET', requestURL, true);
                    getReq.channel.loadFlags |= hfCI.nsIRequest.LOAD_BYPASS_CACHE;
                    getReq.onreadystatechange = function (aEvt) {
                        if (getReq.readyState == 4)
                            httpsfinder.Detect.handleDetectionResponse(aBrowser, getReq, requestURL);
                    };
                    getReq.send(null);
                }
            }
        };
        headReq.send(null);
    }
}

//Get load flags for HTTP observer. We use these to filter normal http requests from page load requests
function getStringArrayOfLoadFlags (flags) {
    var flagsArr = [];

    //Look for the two load flags that indicate a page load (ignore others)
    if (flags & hfCI.nsIChannel.LOAD_DOCUMENT_URI)
        flagsArr.push("LOAD_DOCUMENT_URI");
    if (flags & hfCI.nsIChannel.LOAD_INITIAL_DOCUMENT_URI)
        flagsArr.push("LOAD_INITIAL_DOCUMENT_URI");

    return flagsArr;
}

//Used by HTTP observer to match requests to tabs
function getBrowserFromChannel (aChannel) {
    try {
        var notificationCallbacks = aChannel.notificationCallbacks ? aChannel.notificationCallbacks : aChannel.loadGroup.notificationCallbacks;
        if (!notificationCallbacks)
            return null;
        var domWin = notificationCallbacks.getInterface(hfCI.nsIDOMWindow);
        return gBrowser.getBrowserForDocument(domWin.top.document);
    }
    catch (e) {
        return null;
    }
}

//If good SSL has alread been found during this session, skip new Detection and use this function
function handleCachedSSL (aBrowser, request){
    if(request.responseStatus != 200 && request.responseStatus != 301 && request.responseStatus != 302)
        return;

    if(!httpsfinder.Overlay.isWhitelisted(aBrowser.currentURI.host))
        httpsfinder.Cookies.goodSSLFound(aBrowser.currentURI.host);
    
    var nb = gBrowser.getNotificationBox(aBrowser);
    var sslFoundButtons = [{
        label: httpsfinder.strings.getString("httpsfinder.main.whitelist"),
        accessKey: httpsfinder.strings.getString("httpsfinder.main.whitelistKey"),
        popup: null,
        callback: httpsfinder.Overlay.whitelistDomain
    },{
        label: httpsfinder.strings.getString("httpsfinder.main.noRedirect"),
        accessKey: httpsfinder.strings.getString("httpsfinder.main.noRedirectKey"),
        popup: null,
        callback: httpsfinder.Overlay.redirectNotNow
    },{
        label: httpsfinder.strings.getString("httpsfinder.main.yesRedirect"),
        accessKey: httpsfinder.strings.getString("httpsfinder.main.yesRedirectKey"),
        popup: null,
        callback: httpsfinder.Overlay.redirect
    }];


    if(httpsfinder.prefs.getBoolPref("autoforward"))
        httpsfinder.Overlay.redirectAuto(aBrowser, request);
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
}

//Callback function for our HTTPS Detection request
function handleDetectionResponse (aBrowser, sslTest){
    //Session whitelist host and return if cert is bad or status is not OK.
    var host = sslTest.channel.URI.host.toLowerCase();
    var request = sslTest.channel;

    var cacheExempt = (httpsfinder.Detect.cacheExempt.indexOf(host) != -1) ? true : false;

    if(cacheExempt){
        if(httpsfinder.debug)
            dump("httpsfinder removing " + host + " from whitelist (exempt from saving results on this host)\n");
        httpsfinder.Overlay.removeFromWhitelist(null, aBrowser.contentDocument.baseURIObject.host.toLowerCase());
    }

    var Codes = [200, 301, 302, 0];

    if(Codes.indexOf(sslTest.status) == -1 && httpsfinder.results.goodSSL.indexOf(host) == -1){
        if(httpsfinder.debug)
            dump("httpsfinder leaving " + host + " in whitelist (return status code " + sslTest.status + ")\n");
        return;
    }
    else if(sslTest.status == 0 && !httpsfinder.Detect.testCertificate(request,sslTest.status, aBrowser) && httpsfinder.results.goodSSL.indexOf(host) == -1){
        if(httpsfinder.debug)
            dump("httpsfinder leaving " + host + " in whitelist (bad SSL certificate)\n");
        return;
    }
    else if(!httpsfinder.Detect.testCertificate(request, null, null) && httpsfinder.results.goodSSL.indexOf(host) == -1){
        if(httpsfinder.debug)
            dump("httpsfinder leaving " + host + " in whitelist (bad SSL certificate)\n");
        return;
    }
    else
        httpsfinder.Overlay.removeFromWhitelist(null, host);          
          
    //If the code gets to this point, the HTTPS is good.
        
    //Push host to good SSL list (remember result and skip repeat Detection)
    if(httpsfinder.results.goodSSL.indexOf(host) == -1 && !httpsfinder.pbs.privateBrowsingEnabled){
        if(httpsfinder.debug) dump("Pushing " + host + " to good SSL list\n");

        httpsfinder.Overlay.removeFromWhitelist(null,host);
        if(!cacheExempt)
            httpsfinder.Detect.addHostToGoodSSLList(host);
    }
    else if(!httpsfinder.results.goodSSL.indexOf(aBrowser.contentDocument.baseURIObject.host.toLowerCase()) == -1
        && !httpsfinder.pbs.privateBrowsingEnabled){
        var altHost = aBrowser.contentDocument.baseURIObject.host.toLowerCase();
        if(httpsfinder.debug) dump("Pushing " + altHost + " to good SSL list.\n");

        httpsfinder.Overlay.removeFromWhitelist(null,altHost);
        if(!cacheExempt)
            httpsfinder.Detect.addHostToGoodSSLList(altHost);
    }

    //Check setting and automatically enforce HTTPS
    if(httpsfinder.prefs.getBoolPref("autoforward"))
        httpsfinder.Overlay.redirectAuto(aBrowser, request);

    //If auto-enforce is disabled, if host is not in tempNoAlerts (rule already saved)
    //and HTTPS Found alerts are enabled, alert user of good HTTPS
    else  if(httpsfinder.results.tempNoAlerts.indexOf(request.URI.host) == -1 &&
        httpsfinder.prefs.getBoolPref("httpsfoundalert")){
        if(httpsfinder.Detect.hostsMatch(aBrowser.contentDocument.baseURIObject.host.toLowerCase(),host)){

            var nb = gBrowser.getNotificationBox(aBrowser);
            var sslFoundButtons = [{
                label: httpsfinder.strings.getString("httpsfinder.main.whitelist"),
                accessKey: httpsfinder.strings.getString("httpsfinder.main.whitelistKey"),
                popup: null,
                callback: httpsfinder.Overlay.whitelistDomain
            },{
                label: httpsfinder.strings.getString("httpsfinder.main.noRedirect"),
                accessKey: httpsfinder.strings.getString("httpsfinder.main.noRedirectKey"),
                popup: null,
                callback: httpsfinder.Overlay.redirectNotNow
            },{
                label: httpsfinder.strings.getString("httpsfinder.main.yesRedirect"),
                accessKey: httpsfinder.strings.getString("httpsfinder.main.yesRedirectKey"),
                popup: null,
                callback: httpsfinder.Overlay.redirect
            }];

            nb.appendNotification(httpsfinder.strings.getString("httpsfinder.main.httpsFoundPrompt"),
                "httpsfinder-https-found",'chrome://httpsfinder/skin/httpsAvailable.png',
                nb.PRIORITY_INFO_HIGH, sslFoundButtons);
            httpsfinder.Overlay.removeFromWhitelist(aBrowser.contentDocument, null);

            if(httpsfinder.prefs.getBoolPref("dismissAlerts"))
                setTimeout(function(){
                    httpsfinder.removeNotification("httpsfinder-https-found")
                },httpsfinder.prefs.getIntPref("alertDismissTime") * 1000, 'httpsfinder-https-found');
        }
        else{
            //Catches certain browser location changes and page content that had load flags to fire Detection
            if(httpsfinder.debug)
                dump("Host mismatch, alert blocked (Document: " +
                    aBrowser.contentDocument.baseURIObject.host.toLowerCase() + " , Detection host: " + host + "\n");
        }
    }
}

function addHostToGoodSSLList(host) {    
    httpsfinder.results.goodSSL.push(host);
    httpsfinder.Cookies.goodSSLFound(host);
}

//Certificate testing done before alerting user of https presence
function testCertificate (channel, status, aBrowser) {
    var secure = false;
    try {
        if (! channel instanceof  hfCI.nsIChannel){
            if(httpsfinder.debug)
                dump("httpsfinder testCertificate: Invalid channel object\n");
            return false;
        }

        var secInfo = channel.securityInfo;
        if (secInfo instanceof hfCI.nsITransportSecurityInfo) {
            secInfo.QueryInterface(hfCI.nsITransportSecurityInfo);
            // Check security state flags
            if ((secInfo.securityState & hfCI.nsIWebProgressListener.STATE_IS_SECURE) ==
                hfCI.nsIWebProgressListener.STATE_IS_SECURE)
                secure = true;
        }
        //Check SSL certificate details
        if (secInfo instanceof hfCI.nsISSLStatusProvider) {
            var cert = secInfo.QueryInterface(hfCI.nsISSLStatusProvider).
            SSLStatus.QueryInterface(hfCI.nsISSLStatus).serverCert;
            var verificationResult = cert.verifyForUsage(hfCI.nsIX509Cert.CERT_USAGE_SSLServer);
               
            switch (verificationResult) {
                case hfCI.nsIX509Cert.VERIFIED_OK:
                    if(status != 0)
                        secure = true;                       
                    break;
                case hfCI.nsIX509Cert.NOT_VERIFIED_UNKNOWN:
                    secure = false;
                    break;
                case hfCI.nsIX509Cert.CERT_REVOKED:
                    secure = false;
                    break;
                case hfCI.nsIX509Cert.CERT_EXPIRED:
                    secure = false;
                    break;
                case hfCI.nsIX509Cert.CERT_NOT_TRUSTED:
                    secure = false;
                    break;
                case hfCI.nsIX509Cert.ISSUER_NOT_TRUSTED:
                    if(httpsfinder.prefs.getBoolPref("allowSelfSignedCerts")){
                            
                        var nb = gBrowser.getNotificationBox(aBrowser);
                            
                        var wlButton = [{
                            label: httpsfinder.strings.getString("httpsfinder.main.whitelist"),
                            accessKey: httpsfinder.strings.getString("httpsfinder.main.whitelistKey"),
                            popup: null,
                            callback: httpsfinder.Overlay.whitelistDomain
                        },{
                            label: httpsfinder.strings.getString("httpsfinder.main.yesRedirect"),
                            accessKey: httpsfinder.strings.getString("httpsfinder.main.yesRedirectKey"),
                            popup: null,
                            callback: httpsfinder.Overlay.redirect
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
                case hfCI.nsIX509Cert.ISSUER_UNKNOWN:
                    secure = false;
                    break;
                case hfCI.nsIX509Cert.INVALID_CA:
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
        hfCU.reportError("HTTPS Finder: testCertificate error: " + err.toString() + "\n");
    } 
    if(httpsfinder.debug && secure)
        dump("httpsfinder testCertificate: cert OK (on "+
            channel.URI.host.toLowerCase()+ ")\n");         
    return secure;
}