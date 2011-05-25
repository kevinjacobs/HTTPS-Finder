if (!httpsfinder) var httpsfinder = {};

httpsfinder.rulePreview = {

    httpsfinderLoadRulePreview: function(doc){
        document.getElementById('ruleBox').value = window.arguments[0].inn.rule;
    },

    httpsfinderOkRulePreview: function(doc){
        window.arguments[0].out = {
            rule:document.getElementById("ruleBox").value
            };
    }
};