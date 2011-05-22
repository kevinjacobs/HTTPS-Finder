function httpsfinderLoadRulePreview(doc){
    document.getElementById('ruleBox').value = window.arguments[0].inn.rule;
}

function httpsfinderOkRulePreview(doc){
    window.arguments[0].out = { rule:document.getElementById("ruleBox").value};
    
}