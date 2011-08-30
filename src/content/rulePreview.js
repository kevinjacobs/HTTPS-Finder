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

if (!httpsfinder) var httpsfinder = {};

httpsfinder.rulePreview = {

    //Load window - populate textbox with generated rule
    httpsfinderLoadRulePreview: function(doc){
        document.getElementById('ruleBox').value = window.arguments[0].inn.rule;
    },

    //User clicked ok - return textbox contents as rule
    httpsfinderOkRulePreview: function(doc){
        window.arguments[0].out = {
            rule:document.getElementById("ruleBox").value
            };
    }
};