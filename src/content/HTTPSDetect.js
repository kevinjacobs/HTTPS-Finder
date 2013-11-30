/*
 * HTTPSDetect.js handles background Detection and http observation
 */

httpsfinder.Cookies = {};
httpsfinder_INCLUDE('Cookies', httpsfinder.Cookies);
var OS = Cc["@mozilla.org/observer-service;1"]
        .getService(Ci.nsIObserverService);
////Not a great solution, but this is for problematic domains.
//Google image search over ssl is one, so we won't cache results there.
var cacheExempt = ["www.google.com", "translate.google.com", "encrypted.google.com"];
function QueryInterface(aIID) {
    if (aIID.equals(Ci.nsIObserver) || aIID.equals(Ci.nsISupports))
        return this;
    throw Cr.NS_NOINTERFACE;
}

//Watches HTTP responses, filters and calls Detection if needed
function observe(request, aTopic, aData) {
    if (aTopic == "http-on-examine-response") {
        request.QueryInterface(Ci.nsIHttpChannel);
        if (!httpsfinder.prefs.getBoolPref("enable"))
            return;
        if ((request.responseStatus == 200 || request.responseStatus == 301
                || request.responseStatus == 304) && request.URI.scheme == "http")
            var loadFlags = httpsfinder.Detect.getStringArrayOfLoadFlags(request.loadFlags);
        else
            return;
        if (loadFlags.indexOf("LOAD_DOCUMENT_URI") != -1 && loadFlags.indexOf("LOAD_INITIAL_DOCUMENT_URI") != -1) {
            if (httpsfinder.Overlay.isWhitelisted(request.URI.host.toLowerCase())) {
                if (httpsfinder.debug)
                    dump("Canceling Detection on " + request.URI.host.toLowerCase() + ". Host is whitelisted\n");
                return;
            }
            var browser = httpsfinder.Detect.getBrowserFromChannel(request);
            if (browser == null) {
                if (httpsfinder.debug)
                    dump("httpsfinder browser cannot be found for channel\n");
                return;
            }

            var host = request.URI.host.toLowerCase();
            try {
                if (httpsfinder.Detect.hostsMatch(browser.contentDocument.baseURIObject.host.toLowerCase(), host) &&
                        httpsfinder.results.goodSSL.indexOf(request.URI.host.toLowerCase()) != -1) {
                    if (httpsfinder.debug)
                        dump("Canceling Detection on " + request.URI.host.toLowerCase() + ". Good SSL already cached for host.\n");
                    httpsfinder.Detect.handleCachedSSL(browser, request);
                    return;
                }
            } catch (e) {
                if (e.name == 'NS_ERROR_FAILURE')
                    dump("HTTPS Finder: cannot match URI to browser request.\n");
            }

//Push to whitelist so we don't spam with multiple Detection requests - may be removed later depending on result
            if (!httpsfinder.Overlay.isWhitelisted(host) &&
                    !httpsfinder.pbs.privateBrowsingEnabled) {
                httpsfinder.results.whitelist.push(host);
                if (httpsfinder.debug) {
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

function unregister() {
    try {
        OS.removeObserver(httpsfinder.Detect, "http-on-examine-response");
    }
    catch (e) {/* already removed if enabled pref is false */
    }
}

function hostsMatch(host1, host2) {
//check domain name of page location and detected host. Slice after first . to ignore subdomains
    if (host1.slice(host1.indexOf(".", 0) + 1, host1.length) == host2.slice(host2.indexOf(".", 0) + 1, host2.length))
        return true;
    else
        return false;
}

//HTTPS Detection function - does HEAD falling back to GET, or just GET depending on user settings
function detectSSL(aBrowser, request) {
    var requestURL = request.URI.asciiSpec.replace("http://", "https://");
    //If user preference specifies GET Detection only
    if (!httpsfinder.prefs.getBoolPref("headfirst")) {
        var getReq = new XMLHttpRequest();
        getReq.mozBackgroundRequest = true;
        getReq.open('GET', requestURL, true);
        getReq.channel.loadFlags |= Ci.nsIRequest.LOAD_BYPASS_CACHE;
        getReq.addEventListener("error",
                function(e) {
                    handleDetectionResponse(aBrowser, getReq)
                },false);
        getReq.onload = function(e) {
            handleDetectionResponse(aBrowser, getReq)
        };
        getReq.send(null);
    }
    else { //Otherwise, try HEAD and fall back to GET if necessary (default bahavior)
        var headReq = new XMLHttpRequest();
        headReq.mozBackgroundRequest = true;
        headReq.open('HEAD', requestURL, true);
        headReq.channel.loadFlags |= Ci.nsIRequest.LOAD_BYPASS_CACHE;
        headReq.onreadystatechange = function(aEvt) {
            if (headReq.readyState == 4) {
                if (headReq.status == 200 || headReq.status == 0 ||
                        (headReq.status != 405 && headReq.status != 403))
                    httpsfinder.Detect.handleDetectionResponse(aBrowser, headReq);
                else if (headReq.status == 405 || headReq.status == 403) {
                    dump("httpsfinder Detection falling back to GET for " + requestURL + "\n");
                    var getReq = new XMLHttpRequest();
                    getReq.mozBackgroundRequest = true;
                    getReq.open('GET', requestURL, true);
                    getReq.channel.loadFlags |= Ci.nsIRequest.LOAD_BYPASS_CACHE;
                    getReq.addEventListener("error",
                            function(e) {
                                handleDetectionResponse(aBrowser, getReq)
                            },false);
                    getReq.onload = function(e) {
                        handleDetectionResponse(aBrowser, getReq)
                    };
                    getReq.send(null);
                }
            }
        };
        headReq.send(null);
    }
}

//Get load flags for HTTP observer. We use these to filter normal http requests from page load requests
function getStringArrayOfLoadFlags(flags) {
    var flagsArr = [];
    //Look for the two load flags that indicate a page load (ignore others)
    if (flags & Ci.nsIChannel.LOAD_DOCUMENT_URI)
        flagsArr.push("LOAD_DOCUMENT_URI");
    if (flags & Ci.nsIChannel.LOAD_INITIAL_DOCUMENT_URI)
        flagsArr.push("LOAD_INITIAL_DOCUMENT_URI");
    return flagsArr;
}

//Used by HTTP observer to match requests to tabs
function getBrowserFromChannel(aChannel) {
    try {
        var notificationCallbacks = aChannel.notificationCallbacks ? aChannel.notificationCallbacks : aChannel.loadGroup.notificationCallbacks;
        if (!notificationCallbacks)
            return null;
        var domWin = notificationCallbacks.getInterface(Ci.nsIDOMWindow);
        return gBrowser.getBrowserForDocument(domWin.top.document);
    }
    catch (e) {
        return null;
    }
}

//If good SSL has alread been found during this session, skip new Detection and use this function
function handleCachedSSL(aBrowser, request) {
    if (request.responseStatus != 200 && request.responseStatus != 301 && request.responseStatus != 302)
        return;
    if (!httpsfinder.Overlay.isWhitelisted(aBrowser.currentURI.host))
        httpsfinder.Cookies.goodSSLFound(aBrowser.currentURI.host);
    var nb = gBrowser.getNotificationBox(aBrowser);
    var sslFoundButtons = [{
            label: httpsfinder.strings.getString("httpsfinder.main.whitelist"),
            accessKey: httpsfinder.strings.getString("httpsfinder.main.whitelistKey"),
            popup: null,
            callback: httpsfinder.Overlay.whitelistDomain
        }, {
            label: httpsfinder.strings.getString("httpsfinder.main.noRedirect"),
            accessKey: httpsfinder.strings.getString("httpsfinder.main.noRedirectKey"),
            popup: null,
            callback: httpsfinder.Overlay.redirectNotNow
        }, {
            label: httpsfinder.strings.getString("httpsfinder.main.yesRedirect"),
            accessKey: httpsfinder.strings.getString("httpsfinder.main.yesRedirectKey"),
            popup: null,
            callback: httpsfinder.Overlay.redirect
        }];
    if (httpsfinder.prefs.getBoolPref("autoforward"))
        httpsfinder.Overlay.redirectAuto(aBrowser, request);
    else if (httpsfinder.results.tempNoAlerts.indexOf(request.URI.host) == -1 &&
            httpsfinder.prefs.getBoolPref("httpsfoundalert")) {

        nb.appendNotification(httpsfinder.strings.getString("httpsfinder.main.httpsFoundPrompt"),
                "httpsfinder-https-found", 'chrome://httpsfinder/skin/httpsAvailable.png',
                nb.PRIORITY_INFO_HIGH, sslFoundButtons);
        if (httpsfinder.prefs.getBoolPref("dismissAlerts"))
            setTimeout(function() {
                httpsfinder.removeNotification("httpsfinder-https-found")
            }, httpsfinder.prefs.getIntPref("alertDismissTime") * 1000, 'httpsfinder-https-found');
    }
}

//Callback function for our HTTPS Detection request
function handleDetectionResponse(aBrowser, sslTest) {
//Session whitelist host and return if cert is bad or status is not OK.
    var host = sslTest.channel.URI.host.toLowerCase();
    var request = sslTest.channel;
    var cacheExempt = (httpsfinder.Detect.cacheExempt.indexOf(host) != -1) ? true : false;
    if (cacheExempt) {
        if (httpsfinder.debug)
            dump("httpsfinder removing " + host + " from whitelist (exempt from saving results on this host)\n");
        httpsfinder.Overlay.removeFromWhitelist(null, aBrowser.contentDocument.baseURIObject.host.toLowerCase());
    }

    var Codes = [200, 301, 302, 0];
    if (Codes.indexOf(sslTest.status) == -1 && httpsfinder.results.goodSSL.indexOf(host) == -1) {
        if (httpsfinder.debug)
            dump("httpsfinder leaving " + host + " in whitelist (return status code " + sslTest.status + ")\n");
        return;
    }
    else if (sslTest.status == 0 && !httpsfinder.Detect.testCertificate(request) && httpsfinder.results.goodSSL.indexOf(host) == -1) {
        if (httpsfinder.debug)
            dump("httpsfinder leaving " + host + " in whitelist (bad SSL certificate)\n");
        return;
    }
    else if (!httpsfinder.Detect.testCertificate(request) && httpsfinder.results.goodSSL.indexOf(host) == -1) {
        if (httpsfinder.debug)
            dump("httpsfinder leaving " + host + " in whitelist (bad SSL certificate)\n");
        return;
    }
    else
        httpsfinder.Overlay.removeFromWhitelist(null, host);
    //If the code gets to this point, the HTTPS is good.
    //Push host to good SSL list (remember result and skip repeat Detection)
    if (httpsfinder.results.goodSSL.indexOf(host) == -1 && !httpsfinder.pbs.privateBrowsingEnabled) {
        if (httpsfinder.debug)
            dump("Pushing " + host + " to good SSL list\n");
        httpsfinder.Overlay.removeFromWhitelist(null, host);
        if (!cacheExempt)
            httpsfinder.Detect.addHostToGoodSSLList(host);
    }
    else if (!httpsfinder.results.goodSSL.indexOf(aBrowser.contentDocument.baseURIObject.host.toLowerCase()) == -1
            && !httpsfinder.pbs.privateBrowsingEnabled) {
        var altHost = aBrowser.contentDocument.baseURIObject.host.toLowerCase();
        if (httpsfinder.debug)
            dump("Pushing " + altHost + " to good SSL list.\n");
        httpsfinder.Overlay.removeFromWhitelist(null, altHost);
        if (!cacheExempt)
            httpsfinder.Detect.addHostToGoodSSLList(altHost);
    }

//Check setting and automatically enforce HTTPS
    if (httpsfinder.prefs.getBoolPref("autoforward"))
        httpsfinder.Overlay.redirectAuto(aBrowser, request);
    //If auto-enforce is disabled, if host is not in tempNoAlerts (rule already saved)
    //and HTTPS Found alerts are enabled, alert user of good HTTPS
    else if (httpsfinder.results.tempNoAlerts.indexOf(request.URI.host) == -1 &&
            httpsfinder.prefs.getBoolPref("httpsfoundalert")) {
        if (httpsfinder.Detect.hostsMatch(aBrowser.contentDocument.baseURIObject.host.toLowerCase(), host)) {

            var nb = gBrowser.getNotificationBox(aBrowser);
            var sslFoundButtons = [{
                    label: httpsfinder.strings.getString("httpsfinder.main.whitelist"),
                    accessKey: httpsfinder.strings.getString("httpsfinder.main.whitelistKey"),
                    popup: null,
                    callback: httpsfinder.Overlay.whitelistDomain
                }, {
                    label: httpsfinder.strings.getString("httpsfinder.main.noRedirect"),
                    accessKey: httpsfinder.strings.getString("httpsfinder.main.noRedirectKey"),
                    popup: null,
                    callback: httpsfinder.Overlay.redirectNotNow
                }, {
                    label: httpsfinder.strings.getString("httpsfinder.main.yesRedirect"),
                    accessKey: httpsfinder.strings.getString("httpsfinder.main.yesRedirectKey"),
                    popup: null,
                    callback: httpsfinder.Overlay.redirect
                }];
            nb.appendNotification(httpsfinder.strings.getString("httpsfinder.main.httpsFoundPrompt"),
                    "httpsfinder-https-found", 'chrome://httpsfinder/skin/httpsAvailable.png',
                    nb.PRIORITY_INFO_HIGH, sslFoundButtons);
            httpsfinder.Overlay.removeFromWhitelist(aBrowser.contentDocument, null);
            if (httpsfinder.prefs.getBoolPref("dismissAlerts"))
                setTimeout(function() {
                    httpsfinder.removeNotification("httpsfinder-https-found")
                }, httpsfinder.prefs.getIntPref("alertDismissTime") * 1000, 'httpsfinder-https-found');
        }
        else {
//Catches certain browser location changes and page content that had load flags to fire Detection
            if (httpsfinder.debug)
                dump("Host mismatch, alert blocked (Document: " +
                        aBrowser.contentDocument.baseURIObject.host.toLowerCase() + " , Detection host: " + host + "\n");
        }
    }
}

function addHostToGoodSSLList(host) {
    httpsfinder.results.goodSSL.push(host);
    httpsfinder.Cookies.goodSSLFound(host);
}

// Adapted from the patch for mozTCPSocket error reporting (bug 861196).

function createTCPErrorFromFailedXHR(channel) {
    var status = channel.QueryInterface(Ci.nsIRequest).status;
    var errType;
    var errName;
    if ((status & 0xff0000) === 0x5a0000) { // Security module
        var nsINSSErrorsService = Ci.nsINSSErrorsService;
        var nssErrorsService = Cc['@mozilla.org/nss_errors_service;1'].getService(nsINSSErrorsService);
        var errorClass;
        // getErrorClass will throw a generic NS_ERROR_FAILURE if the error code is
        // somehow not in the set of covered errors.
        try {
            errorClass = nssErrorsService.getErrorClass(status);
        } catch (ex) {
            errorClass = 'SecurityProtocol';
        }
        if (errorClass == nsINSSErrorsService.ERROR_CLASS_BAD_CERT) {
            errType = 'SecurityCertificate';
        } else {
            errType = 'SecurityProtocol';
        }

// NSS_SEC errors (happen below the base value because of negative vals)
        if ((status & 0xffff) < Math.abs(nsINSSErrorsService.NSS_SEC_ERROR_BASE)) {
// The bases are actually negative, so in our positive numeric space, we
// need to subtract the base off our value.
            var nssErr = Math.abs(nsINSSErrorsService.NSS_SEC_ERROR_BASE)
                    - (status & 0xffff);
            switch (nssErr) {
                case 11: // SEC_ERROR_EXPIRED_CERTIFICATE, sec(11)
                    errName = 'SecurityExpiredCertificateError';
                    break;
                case 12: // SEC_ERROR_REVOKED_CERTIFICATE, sec(12)
                    errName = 'SecurityRevokedCertificateError';
                    break;
                    // per bsmith, we will be unable to tell these errors apart very soon,
                    // so it makes sense to just folder them all together already.
                case 13: // SEC_ERROR_UNKNOWN_ISSUER, sec(13)
                case 20: // SEC_ERROR_UNTRUSTED_ISSUER, sec(20)
                case 21: // SEC_ERROR_UNTRUSTED_CERT, sec(21)
                case 36: // SEC_ERROR_CA_CERT_INVALID, sec(36)
                    errName = 'SecurityUntrustedCertificateIssuerError';
                    break;
                case 90: // SEC_ERROR_INADEQUATE_KEY_USAGE, sec(90)
                    errName = 'SecurityInadequateKeyUsageError';
                    break;
                case 176: // SEC_ERROR_CERT_SIGNATURE_ALGORITHM_DISABLED, sec(176)
                    errName = 'SecurityCertificateSignatureAlgorithmDisabledError';
                    break;
                default:
                    errName = 'SecurityError';
                    break;
            }
        }
        else {
            var sslErr = Math.abs(nsINSSErrorsService.NSS_SSL_ERROR_BASE) - (status & 0xffff);
            switch (sslErr) {
                case 3: // SSL_ERROR_NO_CERTIFICATE, ssl(3)
                    errName = 'SecurityNoCertificateError';
                    break;
                case 4: // SSL_ERROR_BAD_CERTIFICATE, ssl(4)
                    errName = 'SecurityBadCertificateError';
                    break;
                case 8: // SSL_ERROR_UNSUPPORTED_CERTIFICATE_TYPE, ssl(8)
                    errName = 'SecurityUnsupportedCertificateTypeError';
                    break;
                case 9: // SSL_ERROR_UNSUPPORTED_VERSION, ssl(9)
                    errName = 'SecurityUnsupportedTLSVersionError';
                    break;
                case 12: // SSL_ERROR_BAD_CERT_DOMAIN, ssl(12)
                    errName = 'SecurityCertificateDomainMismatchError';
                    break;
                default:
                    errName = 'SecurityError';
                    break;
            }
        }
    }
    else {
        errType = 'Network';
        switch (status) {
// connect to host:port failed
            case 0x804B000C: // NS_ERROR_CONNECTION_REFUSED, network(13)
                errName = 'ConnectionRefusedError';
                break;
                // network timeout error
            case 0x804B000E: // NS_ERROR_NET_TIMEOUT, network(14)
                errName = 'NetworkTimeoutError';
                break;
                // hostname lookup failed
            case 0x804B001E: // NS_ERROR_UNKNOWN_HOST, network(30)
                errName = 'DomainNotFoundError';
                break;
            case 0x804B0047: // NS_ERROR_NET_INTERRUPT, network(71)
                errName = 'NetworkInterruptError';
                break;
            default:
                errName = 'NetworkError';
                break;
        }
    }

// XXX we have no TCPError implementation right now because it's really hard to
// do on b2g18. On mozilla-central we want a proper TCPError that ideally
// sub-classes DOMError. Bug 867872 has been filed to implement this and
// contains a documented TCPError.webidl that maps all the error codes we use in
// this file to slightly more readable explanations.
    var error = Cc["@mozilla.org/dom-error;1"].createInstance(Ci.nsIDOMDOMError);
    error.wrappedJSObject.init(errName);
    return errName;
    // XXX: errType goes unused
}


//Certificate testing done before alerting user of https presence
function testCertificate(channel) {
    var secure = false;
    try {
        var secInfo = channel.securityInfo;
        // Print general connection security state
        if (secInfo instanceof Ci.nsITransportSecurityInfo) {
            secInfo.QueryInterface(Ci.nsITransportSecurityInfo);
            if ((secInfo.securityState & Ci.nsIWebProgressListener.STATE_IS_SECURE)
                    == Ci.nsIWebProgressListener.STATE_IS_SECURE) {
                secure = true;
            }
        }
        if (!secure){
            dump(createTCPErrorFromFailedXHR(channel));
            Cu.reportError("HTTPS Finder: testCertificate error: " + err.toString() + "\n");
        }
    }
    catch (err) {
        secure = false;
        Cu.reportError("HTTPS Finder: testCertificate error: " + err.toString() + "\n");
    }
    if (httpsfinder.debug && secure)
        dump("httpsfinder testCertificate: cert OK (on " +
                channel.URI.host.toLowerCase() + ")\n");
    return secure;
}