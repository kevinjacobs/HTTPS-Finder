//Need to fix function names - they're wrapped now so the extra 'httpsfinder' can be removed.
//'use strict';


if (!httpsfinder) var httpsfinder = {};

httpsfinder.preferences = {
    viewMode: "good",

    loadWindowObjects: function(){
        Components.utils.import("resource://hfShared/hfShared.js", httpsfinder.preferences);

        var enable = document.getElementById('enable');
        if(enable.checked){
            document.getElementById('noruleprompt').disabled = false;
            document.getElementById('promptLabel').disabled = false;
            document.getElementById('autoforward').disabled = false;
            document.getElementById('autoforwardLabel').disabled = false;
            document.getElementById('whitelistURL').disabled = false;
            document.getElementById('whitelistURLLabel').disabled = false;
            document.getElementById('whitelist').disabled = false;
        }
        else{
            document.getElementById('noruleprompt').disabled = true;
            document.getElementById('promptLabel').disabled = true;
            document.getElementById('autoforward').disabled = true;
            document.getElementById('autoforwardLabel').disabled = true;
            document.getElementById('whitelistURL').disabled = true;
            document.getElementById('whitelistURLLabel').disabled = true;
            document.getElementById('whitelist').disabled = true;
        }

        var autoforward = document.getElementById('autoforward');
        if(autoforward.checked || !enable.checked){
            document.getElementById('httpsfoundprompt').disabled = true;
            document.getElementById('httpsfoundpromptLbl').disabled = true;
        }
        else if(!autoforward.checked && enable.checked){
            document.getElementById('httpsfoundprompt').disabled = false;
            document.getElementById('httpsfoundpromptLbl').disabled = false;
        }
           
        httpsfinder.preferences.LoadWhitelist();
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
    },

    cycleResultListView: function(){
        var theList = document.getElementById('cacheList');
        while(theList.itemCount > 0)
            for(var i=0; i < theList.itemCount; i++)
                theList.removeItemAt(i);
        
        if(httpsfinder.preferences.viewMode == "good"){
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
            httpsfinder.preferences.viewMode = "bad";
            document.getElementById('cycleResultView').label = "See Good Results"
        }
        else if(httpsfinder.preferences.viewMode == "bad"){
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
            httpsfinder.preferences.viewMode = "good";
            document.getElementById('cycleResultView').label = "See Bad Results"
        }
    },


    //Import whitelist and populate listbox with rules
    LoadWhitelist: function(){
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
                    dump("httpsfinder database error " + anError.message);
                },
                handleCompletion: function(aReason){
                    if (aReason != Components.interfaces.mozIStorageStatementCallback.REASON_FINISHED)
                        dump("httpsfinder database error " + aReason.message);
                }
            });
        }
        catch(e){
            Components.utils.reportError("httpsfinder loadWhitelist " + e);
        }
        finally{
            statement.reset();
            mDBConn.asyncClose()
        }
    },

    //Push user specified rule to sqlite db
    AddToWhitelist: function(){
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
                    dump("httpsfinder whitelist rule add error " + anError.message);
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
            Components.utils.reportError("httpsfinder addToWhitelist " + e);
        }
        finally{
            statement.reset();
            mDBConn.asyncClose()
        }

    },

    //Remove rule, place back in textbox for editing (not the best solution but it works)
    ModifyWhitelistRule: function(){
        var theList = document.getElementById('whitelist');
        theList.ensureIndexIsVisible(theList.selectedIndex);
        if(!theList.selectedItem.firstChild.getAttribute("label"))
            return;
        document.getElementById('whitelistURL').value = theList.selectedItem.firstChild.getAttribute("label");
        httpsfinder.preferences.RemoveWhitelistRule();
    },

    removeCacheItem: function(){
        var theList = document.getElementById('cacheList');
        theList.ensureIndexIsVisible(theList.selectedIndex);
        
        var selectedItems = theList.selectedItems;

        if(httpsfinder.preferences.viewMode == "good"){
            for(let i = 0; i < httpsfinder.preferences.results.goodSSL.length; i++){
                if(httpsfinder.preferences.results.goodSSL[i] == selectedItems[0].firstChild.getAttribute("label"))
                    httpsfinder.preferences.results.goodSSL.splice(i,1);
            }
        }
        else if(httpsfinder.preferences.viewMode == "bad"){
            for(let i = 0; i < httpsfinder.preferences.results.whitelist.length; i++){
                if(httpsfinder.preferences.results.whitelist[i] == selectedItems[0].firstChild.getAttribute("label"))
                    httpsfinder.preferences.results.whitelist.splice(i,1);           

            }
        }

        while(theList.itemCount > 0)
            for(var i=0; i < theList.itemCount; i++)
                theList.removeItemAt(i);


        httpsfinder.preferences.loadResults();

    },

    //Delete selected rule(s) from whitelist
    RemoveWhitelistRule: function(){
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
                    dump("httpsfinder whitelist rule delete error " + anError.message);
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
            Components.utils.reportError("httpsfinder removeFromWhitelist " + e);
        }
        finally{
            statement.reset();
            mDBConn.asyncClose()
        }
    },

    autoForwardToggle: function(){
        var autoforward = document.getElementById('autoforward');

        if(autoforward.checked){
            document.getElementById('httpsfoundprompt').disabled = false;
            document.getElementById('httpsfoundpromptLbl').disabled = false;
        }
        else{
            document.getElementById('httpsfoundprompt').disabled = true;
            document.getElementById('httpsfoundpromptLbl').disabled = true;
        }
    },

    EnableChecked: function(){
        var enable = document.getElementById('enable');
        var autoforward = document.getElementById('autoforward');

        if(enable.checked){
            document.getElementById('noruleprompt').disabled = true;
            document.getElementById('promptLabel').disabled = true;
            document.getElementById('autoforward').disabled = true;
            document.getElementById('autoforwardLabel').disabled = true;
            document.getElementById('whitelistURL').disabled = true;
            document.getElementById('whitelistURLLabel').disabled = true;
            document.getElementById('modifyRule').disabled = true;
            document.getElementById('removeRule').disabled = true;
            document.getElementById('whitelist').disabled = true;

            if(autoforward.checked){
                document.getElementById('httpsfoundprompt').disabled = true;
                document.getElementById('httpsfoundpromptLbl').disabled = true;
            }
            else{
                document.getElementById('httpsfoundprompt').disabled = false;
                document.getElementById('httpsfoundpromptLbl').disabled = false;
            }
        }
        else{
            document.getElementById('noruleprompt').disabled = false;
            document.getElementById('promptLabel').disabled = false;
            document.getElementById('autoforward').disabled = false;
            document.getElementById('autoforwardLabel').disabled = false;
            document.getElementById('whitelistURL').disabled = false;
            document.getElementById('whitelistURLLabel').disabled = false;
            document.getElementById('whitelist').disabled = false;
            
            if(!autoforward.checked){
                document.getElementById('httpsfoundprompt').disabled = false;
                document.getElementById('httpsfoundpromptLbl').disabled = false;
            }

            var theList = document.getElementById('whitelist');

            if(theList.selectedCount == 1){
                document.getElementById('modifyRule').disabled = false;
                document.getElementById('removeRule').disabled = false;
            }

        }
    },

    //Enable and disable modify/remove buttons
    ResultSelect: function(){
        var theList = document.getElementById('cacheList');

        if(theList.selectedCount == 1){
            document.getElementById('viewReport').disabled = false;
            document.getElementById('removeFromCache').disabled = false;
            document.getElementById('writeRule').disabled = false;
        }
        else{
            document.getElementById('viewReport').disabled = true;
            document.getElementById('removeFromCache').disabled = true;
            document.getElementById('writeRule').disabled = false;
        }
    },


    //Enable and disable modify/remove buttons
    WhitelistSelect: function(){
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
    
        httpsfinder.preferences.results.goodSSL.length = 0;
        httpsfinder.preferences.results.goodSSL = [];
        httpsfinder.preferences.results.whitelist.length = 0;
        httpsfinder.preferences.results.whitelist = [];
        httpsfinder.preferences.results.permWhitelistLength = 0;


        var theList = document.getElementById('cacheList');
        while(theList.itemCount > 0)
            for(var i=0; i < theList.itemCount; i++)
                theList.removeItemAt(i);

        httpsfinder.preferences.viewMode = "good";
        document.getElementById('cycleResultView').label = "See Bad Results"
        
        httpsfinder.preferences.loadResults();
    },

    sslReport: function(){
        var theList = document.getElementById('cacheList');
        theList.ensureIndexIsVisible(theList.selectedIndex);
        var selectedItems = theList.selectedItems;
        
        var reportUrl = "https://www.ssllabs.com/ssldb/analyze.html?d=";
        reportUrl += selectedItems[0].firstChild.getAttribute("label");
        reportUrl += "&hideResults=on";

        httpsfinder.preferences.openWebsiteInTab(reportUrl);
    },


    writeRule: function(){
        var theList = document.getElementById('cacheList');
        theList.ensureIndexIsVisible(theList.selectedIndex);
        var selectedItems = theList.selectedItems;

        var eTLDService = Components.classes["@mozilla.org/network/effective-tld-service;1"]
        .getService(Components.interfaces.nsIEffectiveTLDService);


        var hostname = selectedItems[0].firstChild.getAttribute("label");
        var topLevel = "." + eTLDService.getPublicSuffixFromHost(hostname);

        httpsfinder.preferences.sharedWriteRule(hostname, topLevel);
    }

};