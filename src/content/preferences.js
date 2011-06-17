if (!httpsfinder) var httpsfinder = {};

httpsfinder.preferences = {
    //Import whitelist and populate listbox with rules
    httpsfinderLoadWhitelist: function(){
        var theList = document.getElementById('whitelist');
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
                    //Append each rule to the listbox
                    for (let row = aResultSet.getNextRow();   row; row = aResultSet.getNextRow()){
                        var row2 = document.createElement('listitem');
                        var cell = document.createElement('listcell');
                        cell.setAttribute('label', row.getResultByName("rule"));
                        row2.appendChild(cell);
                        theList.appendChild(row2);
                    }
                },
                handleError: function(anError){
                    alert("Error loading rules: " + anError.message);
                    Application.console.log("httpsfinder database error " + anError.message);
                },
                handleCompletion: function(aReason){
                    if (aReason != Components.interfaces.mozIStorageStatementCallback.REASON_FINISHED)
                        Application.console.log("httpsfinder database error " + aReason.message);
                }
            });
        }
        catch(e){
            Application.console.log("httpsfinder loadWhitelist " + e);
        }
        finally{
            statement.reset();
            mDBConn.asyncClose()
        }
    },

    //Push user specified rule to sqlite db
    httpsfinderAddToWhitelist: function(){
        var url = document.getElementById('whitelistURL').value.toLowerCase();
        if(url.length == 0){
            alert("No rule specified");
            return;
        }
        var theList = document.getElementById('whitelist');
        try{
            var file = Components.classes["@mozilla.org/file/directory_service;1"]
            .getService(Components.interfaces.nsIProperties)
            .get("ProfD", Components.interfaces.nsIFile);
            file.append("httpsfinder.sqlite");
            var storageService = Components.classes["@mozilla.org/storage/service;1"]
            .getService(Components.interfaces.mozIStorageService);
            var mDBConn = storageService.openDatabase(file);

            var statement = mDBConn.createStatement("INSERT INTO whitelist (rule) VALUES (?1)");
            statement.bindStringParameter(0, url);
            statement.executeAsync({
                handleResult: function(aResultSet){},
                handleError: function(anError){
                    alert("Error adding rule: " + anError.message);
                    Application.console.log("httpsfinder whitelist rule add error " + anError.message);
                },
                handleCompletion: function(aReason){
                    //Append new rule to list if it was added without error.
                    if (aReason == Components.interfaces.mozIStorageStatementCallback.REASON_FINISHED){
                        var row2 = document.createElement('listitem');
                        var cell = document.createElement('listcell');
                        cell.setAttribute("label", url);
                        row2.appendChild(cell);
                        theList.appendChild(row2);
                        var prefs = Components.classes["@mozilla.org/preferences-service;1"].getService(Components.interfaces.nsIPrefService);
                        prefs.setBoolPref("extensions.httpsfinder.whitelistChanged",true);
                        document.getElementById('whitelistURL').value = "";
                    }
                }
            });
        }
        catch(e){
            Application.console.log("httpsfinder addToWhitelist " + e);
        }
        finally{
            statement.reset();
            mDBConn.asyncClose()
        }

    },

    //Remove rule, place back in textbox for editing (not the best solution but it works)
    httpsfinderModifyWhitelistRule: function(){
        var theList = document.getElementById('whitelist');
        theList.ensureIndexIsVisible(theList.selectedIndex);
        if(!theList.selectedItem.firstChild.getAttribute("label"))
            return;
        document.getElementById('whitelistURL').value = theList.selectedItem.firstChild.getAttribute("label");
        httpsfinder.preferences.httpsfinderRemoveWhitelistRule();
    },

    //Delete selected rule(s) from whitelist
    httpsfinderRemoveWhitelistRule: function(){
        var theList = document.getElementById('whitelist');
        theList.ensureIndexIsVisible(theList.selectedIndex);
        var selectedItems = theList.selectedItems;

        if(selectedItems.length == 0)
            return;

        var urls = [];
        for(var i=0; i < selectedItems.length; i++)
            urls.push(selectedItems[i].firstChild.getAttribute("label"));

        try{
            var file = Components.classes["@mozilla.org/file/directory_service;1"]
            .getService(Components.interfaces.nsIProperties)
            .get("ProfD", Components.interfaces.nsIFile);
            file.append("httpsfinder.sqlite");
            var storageService = Components.classes["@mozilla.org/storage/service;1"]
            .getService(Components.interfaces.mozIStorageService);
            var mDBConn = storageService.openDatabase(file);

            var statement = mDBConn.createStatement("DELETE FROM whitelist where rule = (:value)");
            let params = statement.newBindingParamsArray();
            for (let i = 0; i < urls.length; i++){
                let bp = params.newBindingParams();
                bp.bindByName("value", urls[i]);
                params.addParams(bp);
            }
            statement.bindParameters(params);

            statement.executeAsync({
                handleResult: function(aResultSet){},
                handleError: function(anError){
                    alert("Error deleting rule: " + anError.message);
                    Application.console.log("httpsfinder whitelist rule delete error " + anError.message);
                },
                handleCompletion: function(aReason){
                    if (aReason == Components.interfaces.mozIStorageStatementCallback.REASON_FINISHED){
                        //Remove any selected/removed items
                        for(let i=0; i < selectedItems.length; i++){
                            for(let j=0; j < urls.length; j++){
                                if(selectedItems[i].firstChild.getAttribute("label") == urls[j])
                                    theList.removeChild(selectedItems[i]);
                            }
                        }

                        if(theList.getRowCount() == 0){
                            document.getElementById('modifyRule').disabled = true;
                            document.getElementById('removeRule').disabled = true;
                        }
                        var prefs = Components.classes["@mozilla.org/preferences-service;1"].getService(Components.interfaces.nsIPrefService);
                        prefs.setBoolPref("extensions.httpsfinder.whitelistChanged",true);
                    }
                }
            });
        }
        catch(e){
            Application.console.log("httpsfinder removeFromWhitelist " + e);
        }
        finally{
            statement.reset();
            mDBConn.asyncClose()
        }
    },

    //Enable and disable modify/remove buttons
    httpsfinderWhitelistSelect: function(){
        var theList = document.getElementById('whitelist');
        if(theList.selectedCount == 1){
            document.getElementById('modifyRule').disabled = false;
            document.getElementById('removeRule').disabled = false;
        }
        else{
            document.getElementById('modifyRule').disabled = true;
            document.getElementById('removeRule').disabled = false;
        }
    },

    //User clicked "Clear temporary whitelist". Clear whitelist array and reimport
    resetWhitelist: function(){
        var prefs = Components.classes["@mozilla.org/preferences-service;1"].getService(Components.interfaces.nsIPrefService);
        prefs.setBoolPref("extensions.httpsfinder.whitelistChanged",true);
        var strings = document.getElementById("httpsfinderStrings");
        httpsfinder.preferences.popupNotify("HTTPS Finder", strings.getString("httpsfinder.overlay.whitelistReset"));
    },

    //Generic notifier method
    popupNotify: function(title,body){
        try{
            var alertsService = Components.classes["@mozilla.org/alerts-service;1"]
            .getService(Components.interfaces.nsIAlertsService);
            alertsService.showAlertNotification("chrome://httpsfinder/skin/httpRedirect.png",
                title, body, false, "", null);
        }
        catch(e){ /*Do nothing*/ }
    },

    //User clicked link within prefwindow. Open in new tab
    openPage: function(addr){
        var window = Components.classes["@mozilla.org/appshell/window-mediator;1"].getService(Components.interfaces.nsIWindowMediator);
        var browserWindow = window.getMostRecentWindow("navigator:browser").getBrowser();

        var newTab = browserWindow.addTab(addr, null, null);
        browserWindow.selectedTab = newTab;
    }

};