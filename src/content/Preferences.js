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

if(typeof window.hfCI == "undefined") const hfCI = Components.interfaces;
if(typeof window.hfCC == "undefined") const hfCC = Components.classes;
if(typeof window.hfCU == "undefined") const hfCU = Components.utils;

if (!httpsfinder) var httpsfinder = {};

httpsfinder.Preferences = {
    loadWindowObjects: function(){
        hfCU.import("resource://hfShared/hfShared.js", httpsfinder.Preferences);

        var enable = document.getElementById('enable');
        if (enable.checked){
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
        else if (!autoforward.checked && enable.checked){
            document.getElementById('httpsfoundprompt').disabled = false;
            document.getElementById('httpsfoundpromptLbl').disabled = false;
        }

        httpsfinder.Preferences.LoadWhitelist();
        httpsfinder.Preferences.loadResults();
    },

    loadResults: function(){
        var theList = document.getElementById('cacheList');

        var pbs = hfCC["@mozilla.org/privatebrowsing;1"]
        .getService(hfCI.nsIPrivateBrowsingService);

        if (pbs.privateBrowsingEnabled){
            let row = document.createElement('listitem');
            let cell = document.createElement('listcell');
            var strings = document.getElementById("httpsfinderStrings");
            cell.setAttribute('label', strings.getString("httpsfinder.preference.noResultsPB"));
            row.appendChild(cell);
            theList.appendChild(row);
            theList.disabled = true;
            return;
        }

        for (var i = 0; i < httpsfinder.Preferences.results.goodSSL.length; i++)
        {
            //Add domain name to row
            var row = document.createElement('listitem');
            var cell = document.createElement('listcell');
            cell.setAttribute('label', httpsfinder.Preferences.results.goodSSL[i]);
            row.appendChild(cell);

            //Add check mark to row
            var checkIcon = document.createElement('image');
            checkIcon.setAttribute('src', 'chrome://httpsfinder/skin/goodSSL.png');
            var hbox = document.createElement('hbox');
            hbox.appendChild(checkIcon);
            hbox.setAttribute('pack', 'center');
            row.appendChild(hbox);

            //Add row to groupbox
            theList.appendChild(row);
        }
    },

    //Import whitelist and populate listbox with rules
    LoadWhitelist: function(){
        var theList = document.getElementById('whitelist');
        try{
            var file = hfCC["@mozilla.org/file/directory_service;1"]
            .getService(hfCI.nsIProperties).get("ProfD", hfCI.nsIFile);
            file.append("httpsfinder.sqlite");
            var storageService = hfCC["@mozilla.org/storage/service;1"]
            .getService(hfCI.mozIStorageService);
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
                    dump("httpsfinder database error " + anError.message);
                },
                handleCompletion: function(aReason){
                    if (aReason != hfCI.mozIStorageStatementCallback.REASON_FINISHED)
                        dump("httpsfinder database error " + aReason.message);
                }
            });
        }
        catch(e){
            hfCU.reportError("httpsfinder loadWhitelist " + e);
        }
        finally{
            statement.reset();
            mDBConn.asyncClose()
        }
    },

    //Push user specified rule to sqlite db
    AddToWhitelist: function(){
        var url = document.getElementById('whitelistURL').value.toLowerCase();
        if (url.length == 0){
            alert("No rule specified");
            return;
        }
        var theList = document.getElementById('whitelist');
        try{
            var file = hfCC["@mozilla.org/file/directory_service;1"]
            .getService(hfCI.nsIProperties)
            .get("ProfD", hfCI.nsIFile);
            file.append("httpsfinder.sqlite");
            var storageService = hfCC["@mozilla.org/storage/service;1"]
            .getService(hfCI.mozIStorageService);
            var mDBConn = storageService.openDatabase(file);

            var statement = mDBConn.createStatement("INSERT INTO whitelist (rule) VALUES (?1)");
            statement.bindStringParameter(0, url);
            statement.executeAsync({
                handleResult: function(aResultSet){},
                handleError: function(anError){
                    dump("httpsfinder whitelist rule add error " + anError.message);
                },
                handleCompletion: function(aReason){
                    //Append new rule to list if it was added without error.
                    if (aReason == hfCI.mozIStorageStatementCallback.REASON_FINISHED){
                        var row2 = document.createElement('listitem');
                        var cell = document.createElement('listcell');
                        cell.setAttribute("label", url);
                        row2.appendChild(cell);
                        theList.appendChild(row2);
                        var prefs = hfCC["@mozilla.org/preferences-service;1"].getService(hfCI.nsIPrefService);
                        prefs.setBoolPref("extensions.httpsfinder.whitelistChanged",true);
                        document.getElementById('whitelistURL').value = "";
                    }
                }
            });
        }
        catch(e){
            hfCU.reportError("httpsfinder addToWhitelist " + e);
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
        httpsfinder.Preferences.RemoveWhitelistRule();
    },

    //Called when user removess an item from the good SSL list in Preferences > Advanced
    removeCacheItem: function(){
        var theList = document.getElementById('cacheList');
        theList.ensureIndexIsVisible(theList.selectedIndex);

        var selectedItems = theList.selectedItems;

        for (let i = 0; i < httpsfinder.Preferences.results.goodSSL.length; i++){
            if (httpsfinder.Preferences.results.goodSSL[i] == selectedItems[0].firstChild.getAttribute("label"))
                httpsfinder.Preferences.results.goodSSL.splice(i,1);
        }

        while(theList.itemCount > 0)
            theList.removeItemAt(0);

        httpsfinder.Preferences.loadResults();
    },

    //Delete selected rule(s) from whitelist
    RemoveWhitelistRule: function(){
        var theList = document.getElementById('whitelist');
        theList.ensureIndexIsVisible(theList.selectedIndex);
        var selectedItems = theList.selectedItems;

        if (selectedItems.length == 0)
            return;

        var urls = [];
        for (var i=0; i < selectedItems.length; i++)
            urls.push(selectedItems[i].firstChild.getAttribute("label"));

        try{
            var file = hfCC["@mozilla.org/file/directory_service;1"]
            .getService(hfCI.nsIProperties).get("ProfD", hfCI.nsIFile);
            file.append("httpsfinder.sqlite");
            var storageService = hfCC["@mozilla.org/storage/service;1"]
            .getService(hfCI.mozIStorageService);
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
                    dump("httpsfinder whitelist rule delete error " + anError.message);
                },
                handleCompletion: function(aReason){
                    if (aReason == hfCI.mozIStorageStatementCallback.REASON_FINISHED){
                        //Remove any selected/removed items
                        for (let i=0; i < selectedItems.length; i++){
                            for (let j=0; j < urls.length; j++){
                                if (selectedItems[i].firstChild.getAttribute("label") == urls[j])
                                    theList.removeChild(selectedItems[i]);
                            }
                        }

                        if (theList.getRowCount() == 0){
                            document.getElementById('modifyRule').disabled = true;
                            document.getElementById('removeRule').disabled = true;
                        }

                        var prefs = hfCC["@mozilla.org/preferences-service;1"].getService(hfCI.nsIPrefService);
                        prefs.setBoolPref("extensions.httpsfinder.whitelistChanged",true);
                    }
                }
            });
        }
        catch(e){
            hfCU.reportError("httpsfinder removeFromWhitelist " + e);
        }
        finally{
            statement.reset();
            mDBConn.asyncClose()
        }
    },

    autoForwardToggle: function(){
        var autoforward = document.getElementById('autoforward');

        if (autoforward.checked){
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

        if (enable.checked){
            document.getElementById('noruleprompt').disabled = true;
            document.getElementById('promptLabel').disabled = true;
            document.getElementById('autoforward').disabled = true;
            document.getElementById('autoforwardLabel').disabled = true;
            document.getElementById('whitelistURL').disabled = true;
            document.getElementById('whitelistURLLabel').disabled = true;
            document.getElementById('modifyRule').disabled = true;
            document.getElementById('removeRule').disabled = true;
            document.getElementById('whitelist').disabled = true;

            if (autoforward.checked){
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

            if (!autoforward.checked){
                document.getElementById('httpsfoundprompt').disabled = false;
                document.getElementById('httpsfoundpromptLbl').disabled = false;
            }

            var theList = document.getElementById('whitelist');

            if (theList.selectedCount == 1){
                document.getElementById('modifyRule').disabled = false;
                document.getElementById('removeRule').disabled = false;
            }

        }
    },

    //Enable and disable modify/remove buttons
    ResultSelect: function(){
        var theList = document.getElementById('cacheList');

        if (theList.selectedCount == 1){
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

        if (theList.selectedCount == 1){
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
        var prefs = hfCC["@mozilla.org/preferences-service;1"].getService(hfCI.nsIPrefService);
        prefs.setBoolPref("extensions.httpsfinder.whitelistChanged",true);

        var strings = document.getElementById("httpsfinderStrings");
        httpsfinder.Preferences.popupNotify("HTTPS Finder", strings.getString("httpsfinder.overlay.whitelistReset"));

        httpsfinder.Preferences.results.goodSSL.length = 0;
        httpsfinder.Preferences.results.goodSSL = [];
        httpsfinder.Preferences.results.whitelist.length = 0;
        httpsfinder.Preferences.results.whitelist = [];
        httpsfinder.Preferences.results.permWhitelistLength = 0;

        var theList = document.getElementById('cacheList');
        while (theList.itemCount > 0)
            theList.removeItemAt(0);

        httpsfinder.Preferences.loadResults();
    },

    sslReport: function(){
        var theList = document.getElementById('cacheList');
        theList.ensureIndexIsVisible(theList.selectedIndex);
        var selectedItems = theList.selectedItems;

        var reportUrl = "https://www.ssllabs.com/ssldb/analyze.html?d=";
        reportUrl += selectedItems[0].firstChild.getAttribute("label");
        reportUrl += "&hideResults=on";

        httpsfinder.Preferences.openWebsiteInTab(reportUrl);
    },


    writeRule: function(){
        var theList = document.getElementById('cacheList');
        theList.ensureIndexIsVisible(theList.selectedIndex);
        var selectedItems = theList.selectedItems;

        var eTLDService = hfCC["@mozilla.org/network/effective-tld-service;1"]
        .getService(hfCI.nsIEffectiveTLDService);


        var hostname = selectedItems[0].firstChild.getAttribute("label");
        var topLevel = "." + eTLDService.getPublicSuffixFromHost(hostname);

        httpsfinder.Preferences.sharedWriteRule(hostname, topLevel, "");
    }

};