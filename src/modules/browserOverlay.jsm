var EXPORTED_SYMBOLS = ['results', 'popupNotify'];

var results = {
   goodSSL : [],
   permWhitelistLength : 0,
   whitelist : [],
   tempNoAlerts : []
};

    //Generic notifier method
     function popupNotify(title,body){
        try{
            var alertsService = Components.classes["@mozilla.org/alerts-service;1"]
            .getService(Components.interfaces.nsIAlertsService);
            alertsService.showAlertNotification("chrome://httpsfinder/skin/httpRedirect.png",
                title, body, false, "", null);
        }
        catch(e){ /*Do nothing*/ }
    };