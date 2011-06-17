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