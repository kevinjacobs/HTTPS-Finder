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
const Ci = Components.interfaces;
const Cc = Components.classes;
const Cu = Components.utils;

var EXPORTED_SYMBOLS = ['results',
'popupNotify',
'removeNotification',
'openWebsiteInTab',
'sharedWriteRule',
'getHostWithoutSub',
'restartNow',
'alertRuleFinished',
'restoreDefaultCookiesForHost'];

var results = {
    goodSSL : [],
    originallyInsecureCookies: [],
    cookieHostWhitelist : [],
    securedCookieHosts : [],
    permWhitelistLength : 0, //Count for permanent whitelist items (first x items are permanent, the rest are temp)
    whitelist : [],
    tempNoAlerts : []
};

var redirectedTab =  [[]]; //Tab info for pre-redirect URLs.

function restoreDefaultCookiesForHost(host, wildcardHost){
    var cookieManager = Cc["@mozilla.org/cookiemanager;1"]
    .getService(Ci.nsICookieManager2);
    
    var enumerator = cookieManager.getCookiesFromHost(host);
    
    while (enumerator.hasMoreElements()) {
        var cookie = enumerator.getNext().QueryInterface(Components.interfaces.nsICookie2);     
        
        if(cookie.host == host){
            var expiry = Math.min(cookie.expiry, Math.pow(2,31))
            cookieManager.remove(cookie.host, cookie.name, cookie.path, false);
            cookieManager.add(cookie.host, cookie.path, cookie.name, cookie.value, false, cookie.isHTTPOnly, cookie.isSession, expiry);    
        }
        else if(wildcardHost != null && (cookie.host == wildcardHost)){
            expiry = Math.min(cookie.expiry, Math.pow(2,31))
            cookieManager.remove(cookie.host, cookie.name, cookie.path, false);
            cookieManager.add(cookie.host, cookie.path, cookie.name, cookie.value, false, cookie.isHTTPOnly, cookie.isSession, expiry);    
        }
    }
};

//Generic notifier method
function popupNotify(title,body){
    try{
        var alertsService = Cc["@mozilla.org/alerts-service;1"]
        .getService(Ci.nsIAlertsService);
        alertsService.showAlertNotification("chrome://httpsfinder/skin/httpRedirect.png",
            title, body, false, "", null);
    }
    catch(e){ /*Do nothing*/ }
};

function openWebsiteInTab(addr){
    if(typeof gBrowser == "undefined"){
        var window = Cc["@mozilla.org/appshell/window-mediator;1"].getService(Ci.nsIWindowMediator);
        var browserWindow = window.getMostRecentWindow("navigator:browser").getBrowser();
        var newTab = browserWindow.addTab(addr, null, null);
        browserWindow.selectedTab = newTab;

    }
    else
        gBrowser.selectedTab = gBrowser.addTab(addr);
};

//Remove notification called from setTimeout(). Looks through each tab for an alert with mataching key. Removes it, if exists.
function removeNotification(key){
    var windowMediator = Cc["@mozilla.org/appshell/window-mediator;1"]
    .getService(Ci.nsIWindowMediator);

    var currentWindow = windowMediator.getMostRecentWindow("navigator:browser");    

    var browser = currentWindow.gBrowser.selectedBrowser;
    var item = null;
    if (item = currentWindow.getBrowser().getNotificationBox(browser).getNotificationWithValue(key))
        currentWindow.getBrowser().getNotificationBox(browser).removeNotification(item);
};

/*
 * Code below this point is for rule writing
 */

//Passed in uri variable is an asciispec uri from pre-redirect. (i.e. full http://www.domain.com)
function sharedWriteRule(hostname, topLevel, OSXRule){
    var windowMediator = Cc["@mozilla.org/appshell/window-mediator;1"]
    .getService(Ci.nsIWindowMediator);

    var prefService = Cc["@mozilla.org/preferences-service;1"]
    .getService(Ci.nsIPrefService);

    var prefs = prefService.getBranch("extensions.httpsfinder.");
    var currentWindow = windowMediator.getMostRecentWindow("navigator:browser");
    var strings = currentWindow.document.getElementById("httpsfinderStrings");
    
    if(prefs.getBoolPref("useNoscript")){
        var noscriptPrefs = prefService.getBranch("noscript.");
        var existingRules = noscriptPrefs.getCharPref("httpsForced");
        if(existingRules.indexOf(hostname + ",") == -1){
            noscriptPrefs.setCharPref("httpsForced", existingRules + hostname + ",");
            if(this.results.tempNoAlerts.indexOf(hostname) == -1)
                this.results.tempNoAlerts.push(hostname);
            alertRuleFinished(currentWindow.gBrowser.contentDocument);  
        }
        return;
    }
    var title = "";
    var tldLength = topLevel.length - 1;
    if(hostname.indexOf("www.") != -1)
        title = hostname.slice(hostname.indexOf(".",0) + 1,hostname.lastIndexOf(".",0) - tldLength);
    else
        title = hostname.slice(0, hostname.lastIndexOf(".", 0) - tldLength);
    title = title.charAt(0).toUpperCase() + title.slice(1);

    var regTopLevel = topLevel;
    if(topLevel.indexOf(".") != topLevel.lastIndexOf(".")){
        var split = topLevel.split(".");
        regTopLevel = "." + split[0] + split[1] + "\\." + split[2];        
    }
    var from = "^http://(www\\.)?" + title.toLowerCase() + "\\"  + regTopLevel + "/";
    var to = "https://" + title.toLowerCase() + topLevel + "/";
    var rule;
    var versionTag = "\n<!-- Rule generated by HTTPS Finder " + strings.getString("httpsfinder.version") + " -->";


    //One will be "domain.com" and the other will be "www.domain.com"
    var domains = hostname.split(".");
    var name = title + topLevel;
    if(domains.length == 2){
        //Then the hostname is of the form "mysite.com". We add a "www." rule as well in this case.
        var wwwHost =  "www." + hostname;
        to = "https://" + hostname + "/";
	rule = "<ruleset name=";
		rule += "\"" + name + "\"";
		rule += ">\n";

		rule += "<target host=";
		rule += "\"" + hostname + "\"";
		rule += "\/>\n";

		rule += "<target host=";
		rule += "\"" + wwwHost + "\"";
		rule += "\/>\n";

		rule += "<rule from=";
		rule += "\"" + from + "\"";
		rule += " to=\"" + to + "\"\/>\n";
		
		rule += "<\/ruleset>";	
		


        /*rule = <{"ruleset"} name = {name}>
        		<{"target"} host={hostname}/>
        		<{"target"} host={wwwHost}/>
        		<{"rule"} from={from} to={to}/>
               </{'ruleset'}>;
	*/
    }
    else if(domains.length == 3){
        //Then the hostname already contains subdomain info (www or non-www).
        
        //bug fix for issue 38 - properly escape . characters
        if(hostname.indexOf("www.") == -1){
            var fromBits = title.toLowerCase().split(".");
            from = "^http://(www\\.)?" + fromBits[0] + "\\." + fromBits[1]  + "\\"  + topLevel + "/";         
        }
        to = "https://" + hostname + "/";
	rule = "<ruleset name=";
		rule += "\"" + name + "\"";
		rule += ">\n";

		rule += "<target host=";
		rule += "\"" + hostname + "\"";
		rule += "\/>\n";

		rule += "<rule from=";
		rule += "\"" + from + "\"";
		rule += " to=\"" + to + "\"\/>\n";
		
		rule += "<\/ruleset>";
	/*
        rule = <{"ruleset"} name = {name}>
        <{"target"} host={hostname}/>
        <{'rule'} from={from} to={to}/>
        </{"ruleset"}>;
	*/
    }
    else{
        //Catch all
	rule = "<ruleset name=";
	rule += "\"" + name + "\"";
	rule += ">\n";

	rule += "<target host=";
	rule += "\"" + hostname + "\"";
	rule += "\/>\n";

	rule += "<rule from=";
	rule += "\"" + from + "\"";
	rule += " to=\"" + to + "\"\/>\n";
		
	rule += "<\/ruleset>";

	/*
        rule = <{"ruleset"} name = {name}>
        <{"target"} host={hostname}/>
        <{"rule"} from={from} to={to}/>
        </{"ruleset"}>;
	*/
    }

    //OSX returns null parameters unless the rule preview dialog is modal.
    //This mucks up the rule writing from Preferences, since that dialog is also modal.
    //We use OSXRule as a 'flag', and re-call this method from RulePreview if the OS type is Mac (Darwin)
    //OSXRule contains the full contents of the rule preview dialog.
    if(OSXRule == ""){
        if(prefs.getBoolPref("showrulepreview")){
            var params = {
                inn:{
                    rule:rule
                },
                out:null
            };


            //Workaround for how OS X handles modal dialog windows.. If launched from Preferences, it won't show
            //the dialog until prefwindow closes. So we just make the rule preview non-modal here.
        
            // Returns "WINNT" on Windows,"Linux" on GNU/Linux. and "Darwin" on Mac OS X.
            var osString = Cc["@mozilla.org/xre/app-info;1"]
            .getService(Ci.nsIXULRuntime).OS;

            if(osString == "Darwin")
                currentWindow.openDialog("chrome://httpsfinder/content/RulePreview.xul", "",
                    "chrome, dialog, centerscreen, resizable=yes", params).focus();
            else
                currentWindow.openDialog("chrome://httpsfinder/content/RulePreview.xul", "",
                    "chrome, dialog, modal,centerscreen, resizable=yes", params).focus();

            if (!params.out)
                return; //user canceled rule
            else
                rule = params.out.rule; //reassign rule value from the textbox
        }
    }
    else
        rule =  OSXRule; //Optional parameter used on only OSX to get around null parameter output on non-modal rule preview

    title = name; //Re-grab the title from XML for file name (user may have edited it)


    var ostream = Cc["@mozilla.org/network/file-output-stream;1"].
    createInstance(Ci.nsIFileOutputStream);
    var file = Cc["@mozilla.org/file/directory_service;1"].
    getService(Ci.nsIProperties).get("ProfD", Ci.nsIFile);

    file.append("HTTPSEverywhereUserRules")
    file.append(title + ".xml");
    try{
        file.create(Ci.nsIFile.NORMAL_FILE_TYPE, 0666);
    }
    catch(e){
        if(e.name == 'NS_ERROR_FILE_ALREADY_EXISTS'){
            if (currentWindow.confirm(strings.getString("httpsfinder.rulePreview.overwriteConfirm")))
                file.remove(false);               
            else
                return;            
        }
    }
    ostream.init(file, 0x02 | 0x08 | 0x20, 0666, ostream.DEFER_OPEN);
    var converter = Cc["@mozilla.org/intl/scriptableunicodeconverter"].
    createInstance(Ci.nsIScriptableUnicodeConverter);
    converter.charset = "UTF-8";
    
    var istream = null;
    if(prefs.getBoolPref("appendVersionTagToRules"))
        istream = converter.convertToInputStream(rule + versionTag);
    else
        istream = converter.convertToInputStream(rule);
    
    Cu.import("resource://gre/modules/NetUtil.jsm");
    NetUtil.asyncCopy(istream, ostream);

    if(this.results.tempNoAlerts.indexOf(hostname) == -1)
        this.results.tempNoAlerts.push(hostname);

    alertRuleFinished(currentWindow.gBrowser.contentDocument);
};

//return host without subdomain (e.g. input: code.google.com, outpout: google.com)
function getHostWithoutSub(fullHost){
    if(typeof fullHost != 'string')
        return "";
    else
        return fullHost.slice(fullHost.indexOf(".") + 1, fullHost.length);
};

function restartNow(){
    var Application = Cc["@mozilla.org/fuel/application;1"].getService(Ci.fuelIApplication);
    Application.restart();
};

function alertRuleFinished(aDocument){ 
    //Check firefox version and use appropriate method
    var Application = Cc["@mozilla.org/fuel/application;1"]
        .getService(Ci.fuelIApplication);
    var windowMediator = Cc["@mozilla.org/appshell/window-mediator;1"]
        .getService(Ci.nsIWindowMediator);
    var prefService = Cc["@mozilla.org/preferences-service;1"]
        .getService(Ci.nsIPrefService);

    var currentWindow = windowMediator.getMostRecentWindow("navigator:browser");
    var strings = currentWindow.document.getElementById("httpsfinderStrings");
    var prefs = prefService.getBranch("extensions.httpsfinder.");

    var removeNotification = this.removeNotification;

    //Determin FF version and use proper method to check for HTTPS Everywhere
    var appInfo = Components.classes["@mozilla.org/xre/app-info;1"]  
         .getService(Components.interfaces.nsIXULAppInfo);  
    var versionChecker = Components.classes["@mozilla.org/xpcom/version-comparator;1"]  
         .getService(Components.interfaces.nsIVersionComparator);  
                        
    if(versionChecker.compare(appInfo.version, "4.0") >= 0){
        Cu.import("resource://gre/modules/AddonManager.jsm");
        AddonManager.getAddonByID("https-everywhere@eff.org", function(addon) {
            //Addon is null if not installed
            if(addon == null)
                getHTTPSEverywhere();
            else if(addon != null)
                promptForRestart();
        });
    }
    else{  //Firefox versions below 4.0
        if(!Application.extensions.has("https-everywhere@eff.org"))
            getHTTPSEverywhere();
        else
            promptForRestart();
    }

    //Alert user to install HTTPS Everywhere for rule enforcement
    var getHTTPSEverywhere = function() {
        var installButtons = [{
            label: strings.getString("httpsfinder.main.getHttpsEverywhere"),
            accessKey: strings.getString("httpsfinder.main.getHttpsEverywhereKey"),
            popup: null,
            callback: getHE  //Why is this needed? Setting the callback directly automatically calls when there is a parameter
        }];
       
        var nb = currentWindow.gBrowser.getNotificationBox(currentWindow.gBrowser.getBrowserForDocument(aDocument));
        nb.appendNotification(strings.getString("httpsfinder.main.NoHttpsEverywhere"),
            'httpsfinder-getHE','chrome://httpsfinder/skin/httpsAvailable.png',
            nb.PRIORITY_INFO_HIGH, installButtons);
    };

    //See previous comment (in installButtons)
    var getHE = function(){
        this.openWebsiteInTab("http://www.eff.org/https-everywhere/");
    };

    //HTTPS Everywhere is installed. Prompt for restart
    var promptForRestart = function() {
        var nb = currentWindow.gBrowser.getNotificationBox(currentWindow.gBrowser.getBrowserForDocument(aDocument));
        var privatebrowsing = false;
        try {
          // Firefox 20+
          Components.utils.import("resource://gre/modules/PrivateBrowsingUtils.jsm");
          if (!PrivateBrowsingUtils.isWindowPrivate(window)) {
            privatebrowsing = true;
          }
        } catch(e) {
          // pre Firefox 20 (if you do not have access to a doc. 
          // might use doc.hasAttribute("privatebrowsingmode") then instead)
          try {
            privatebrowsing = Components.classes["@mozilla.org/privatebrowsing;1"].
                                    getService(Components.interfaces.nsIPrivateBrowsingService).
                                    privateBrowsingEnabled;
          } catch(e) {
            Components.utils.reportError(e);
          }
        }

        var restartButtons = [{
            label: strings.getString("httpsfinder.main.restartYes"),
            accessKey: strings.getString("httpsfinder.main.restartYesKey"),
            popup: null,
            callback: restartNow
        }];

        if (privatebrowsing)
            nb.appendNotification(strings.getString("httpsfinder.main.restartPromptPrivate"),
                "httpsfinder-restart",'chrome://httpsfinder/skin/httpsAvailable.png',
                nb.PRIORITY_INFO_HIGH, restartButtons);
        else
            nb.appendNotification(strings.getString("httpsfinder.main.restartPrompt"),
                "httpsfinder-restart",'chrome://httpsfinder/skin/httpsAvailable.png',
                nb.PRIORITY_INFO_HIGH, restartButtons);

        if(prefs.getBoolPref("dismissAlerts"))
            currentWindow.setTimeout(function(){
                removeNotification("httpsfinder-restart")
            },prefs.getIntPref("alertDismissTime") * 1000, 'httpsfinder-restart');
    };
};

