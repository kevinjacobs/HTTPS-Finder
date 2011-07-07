//Need to fix function names - they're wrapped now so the extra 'httpsfinder' can be removed.

if (!httpsfinder) var httpsfinder = {};

httpsfinder.preferences = {

    loadWindowObjects: function(){
        Components.utils.import("resource://hfShared/browserOverlay.jsm", httpsfinder.preferences);
        //alert("white": httpsfinder.preferences.results.whitelist); //Testing
        //alert("good": httpsfinder.preferences.results.goodSSL); //Testing

        var enable = document.getElementById('enable');
        if(enable.checked){
            document.getElementById('noruleprompt').disabled = false;
            document.getElementById('promptLabel').disabled = false;
            document.getElementById('autoforward').disabled = false;
            document.getElementById('autoforwardLabel').disabled = false;
            document.getElementById('whitelistURL').disabled = false;
            document.getElementById('whitelistURLLabel').disabled = false;
            document.getElementById('resetWhitelist').disabled = false;
            document.getElementById('whitelist').disabled = false;
        }
        else{
            document.getElementById('noruleprompt').disabled = true;
            document.getElementById('promptLabel').disabled = true;
            document.getElementById('autoforward').disabled = true;
            document.getElementById('autoforwardLabel').disabled = true;
            document.getElementById('whitelistURL').disabled = true;
            document.getElementById('whitelistURLLabel').disabled = true;
            document.getElementById('resetWhitelist').disabled = true;
            document.getElementById('modifyRule').disabled = true;
            document.getElementById('removeRule').disabled = true;
            document.getElementById('whitelist').disabled = true;
        }
        httpsfinder.preferences.httpsfinderLoadWhitelist();
        httpsfinder.preferences.loadResults();
    },

    loadResults: function(){
        var theList = document.getElementById('cacheList');

        for (var i = 0; i < httpsfinder.preferences.results.goodSSL.length; i++)
        {
            var row = document.createElement('listitem');
            var cell = document.createElement('listcell');
            cell.setAttribute('label', httpsfinder.preferences.results.goodSSL[i]);
            row.appendChild(cell);

            cell = document.createElement('listcell');
            cell.setAttribute('label',  "Good" );
            row.appendChild(cell);

            theList.appendChild(row);
        }


        for(var j = httpsfinder.preferences.results.permWhitelistLength;
            j < httpsfinder.preferences.results.whitelist.length; j++){
            var row2 = document.createElement('listitem');
            var cell2 = document.createElement('listcell');
            cell2.setAttribute('label', httpsfinder.preferences.results.whitelist[j]);
            row2.appendChild(cell2);

            cell2 = document.createElement('listcell');
            cell2.setAttribute('label',  "Bad" );
            row2.appendChild(cell2);

            theList.appendChild(row2);
        }


    //        for (let row = aResultSet.getNextRow();   row; row = aResultSet.getNextRow()){
    //            var row2 = document.createElement('listitem');
    //            var cell = document.createElement('listcell');
    //            cell.setAttribute('label', row.getResultByName("rule"));
    //            row2.appendChild(cell);
    //            theList.appendChild(row2);
    //        }
    },

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

    httpsfinderEnableChecked: function(){
        var enable = document.getElementById('enable');
        if(enable.checked){
            document.getElementById('noruleprompt').disabled = true;
            document.getElementById('promptLabel').disabled = true;
            document.getElementById('autoforward').disabled = true;
            document.getElementById('autoforwardLabel').disabled = true;
            document.getElementById('whitelistURL').disabled = true;
            document.getElementById('whitelistURLLabel').disabled = true;
            document.getElementById('resetWhitelist').disabled = true;
            document.getElementById('modifyRule').disabled = true;
            document.getElementById('removeRule').disabled = true;
            document.getElementById('whitelist').disabled = true;
        }
        else{
            document.getElementById('noruleprompt').disabled = false;
            document.getElementById('promptLabel').disabled = false;
            document.getElementById('autoforward').disabled = false;
            document.getElementById('autoforwardLabel').disabled = false;
            document.getElementById('whitelistURL').disabled = false;
            document.getElementById('whitelistURLLabel').disabled = false;
            document.getElementById('resetWhitelist').disabled = false;
            document.getElementById('whitelist').disabled = false;
            var theList = document.getElementById('whitelist');
            if(theList.selectedCount == 1){
                document.getElementById('modifyRule').disabled = false;
                document.getElementById('removeRule').disabled = false;
            }

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
        // httpsfinder.browserOverlay.popupNotify("HTTPS Finder", strings.getString("httpsfinder.overlay.whitelistReset"));
        httpsfinder.preferences.popupNotify("HTTPS Finder", strings.getString("httpsfinder.overlay.whitelistReset"));
        //Move popup Nofity into shared JSM - importing browserOverlay then opening a prefwindow fires init again
    
        httpsfinder.preferences.results.goodSSL.length = 0;
        httpsfinder.preferences.results.goodSSL = [];
        httpsfinder.preferences.results.whitelist.length = 0;
        httpsfinder.preferences.results.whitelist = [];
        httpsfinder.preferences.results.permWhitelistLength = 0;

        var theList = document.getElementById('cacheList');
        while(theList.itemCount > 0)
            for(var i=0; i < theList.itemCount; i++)
                theList.removeItemAt(i);
        httpsfinder.preferences.loadResults();
    }
};