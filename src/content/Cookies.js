/*
 * Cookies.js handles cookie modification (setting securecookie flags)
 */

var cookieManager = Cc["@mozilla.org/cookiemanager;1"]
.getService(Ci.nsICookieManager2);
        

var cookieService = Cc["@mozilla.org/cookieService;1"]
.getService(Ci.nsICookieService);
    
    
var OS = Cc["@mozilla.org/observer-service;1"]
.getService(Ci.nsIObserverService);

var originallyInsecureCookies = [];

function goodSSLFound(host){
    if(httpsfinder.prefs.getBoolPref("attemptSecureCookies")){   
        var enumerator = this.getCookiesFromHost(host);
        while (enumerator.hasMoreElements()) {
            var cookie = enumerator.getNext().QueryInterface(Components.interfaces.nsICookie2);
            if(!cookie.isSecure)
                this.handleInsecureCookie(cookie);
        }
    }
}

function getCookiesFromHost(host){
    return this.cookieManager.getCookiesFromHost(host);
}

function _secureIndividualCookie(cookie) {    
    if(httpsfinder.Overlay.isWhitelisted(cookie.host))
        return;
    
    if(httpsfinder.results.securedCookieHosts.indexOf(cookie.host) == -1)
        httpsfinder.results.securedCookieHosts.push(cookie.host);
    
    this.originallyInsecureCookies.push(cookie.name + ";" + cookie.host + "/" + cookie.path);    
    
    var expiry = Math.min(cookie.expiry, Math.pow(2,31))
    this.cookieManager.remove(cookie.host, cookie.name, cookie.path, false);
    this.cookieManager.add(cookie.host, cookie.path, cookie.name, cookie.value, true, cookie.isHTTPOnly, cookie.isSession, expiry);    
}

//Used for restoring insecure cookies (if user adds domain to whitelist, we restore defaults)
function _insecureIndividualCookie(cookie) { 
    var expiry = Math.min(cookie.expiry, Math.pow(2,31))
    this.cookieManager.remove(cookie.host, cookie.name, cookie.path, false);
    this.cookieManager.add(cookie.host, cookie.path, cookie.name, cookie.value, false, cookie.isHTTPOnly, cookie.isSession, expiry);    
}

function handleInsecureCookie(cookie){
    if(httpsfinder.results.cookieHostWhitelist.indexOf(cookie.host) != -1)
        return;
    
    if(httpsfinder.results.goodSSL.indexOf(cookie.host) != -1){
        this._secureIndividualCookie(cookie);       
    }
    //Only securing wildcard cookies for normal "www.", or "no sub" domains. It seems that most incompatibility problems are 
    //fixed by doing this, since typically specialized subdomains may have HTTPS support whereas the whole site might not.
    //On the other hand, if the www. subdomain has good HTTPS, we're usually safe securing wildcard cookies here.
    else if(httpsfinder.prefs.getBoolPref("secureWildcardCookies")){
        for(var i = 0; i < httpsfinder.results.goodSSL.length; i++){
            var trimmed = httpsfinder.results.goodSSL[i];
            
            if(trimmed.indexOf("www.") != -1 || trimmed.indexOf(".") == trimmed.lastIndexOf(".")){                
                if(trimmed.indexOf(".") != trimmed.lastIndexOf("."))
                    trimmed = trimmed.substring(trimmed.indexOf("."), trimmed.length);    
                else
                    trimmed = "." + trimmed;
                
                if(cookie.host === trimmed)
                    this._secureIndividualCookie(cookie);
            }
        }        
    }
}

function restoreDefaultCookiesForHost(host){
    var enumerator = this.getCookiesFromHost(host);
    while (enumerator.hasMoreElements()) {
        var cookie = enumerator.getNext().QueryInterface(Components.interfaces.nsICookie2);
        
        if(this.originallyInsecureCookies.indexOf(cookie.name + ";" + cookie.host + "/" + cookie.path) != -1
            && cookie.isSecure)
            this._insecureIndividualCookie(cookie);
    }
}

function observe(subject, topic, data) {    
    if(httpsfinder.prefs.getBoolPref("attemptSecureCookies")){
        if (data == "added" || data == "changed") {
            try {
                subject.QueryInterface(CI.nsIArray);
                var elems = subject.enumerate();
                while (elems.hasMoreElements()) {
                    var cookie = elems.getNext()
                    .QueryInterface(CI.nsICookie2);
                    if (!cookie.isSecure) 
                        this.handleInsecureCookie(cookie);                
                }
            } catch(e) {
                subject.QueryInterface(CI.nsICookie2);
                if(!subject.isSecure) 
                    this.handleInsecureCookie(subject);            
            }
        }
    }
}

function register() {
    OS.addObserver(this, "cookie-changed", false);
}

function unregister () {    
    try{
        OS.removeObserver(this, "cookie-changed");
    }
    catch(e){/* already removed if enabled pref is false*/ }
}