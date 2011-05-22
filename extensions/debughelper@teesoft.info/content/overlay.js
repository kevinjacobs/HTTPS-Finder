
var debughelper  = {
    onLoad: function() {
        // initialization code
        this.initialized = true;
        this.gfiltersimportexportBundle = Components.classes["@mozilla.org/intl/stringbundle;1"].getService(Components.interfaces.nsIStringBundleService);
        this.mystrings = this.gfiltersimportexportBundle.createBundle("chrome://debughelper/locale/overlay.properties");
        
        var pref =  Components.classes["@mozilla.org/preferences-service;1"].getService(Components.interfaces.nsIPrefService).getBranch("extensions").QueryInterface(Components.interfaces.nsIPrefBranch2);
        
        pref.setBoolPref(".venkman.enableChromeFilter" ,false);
        
        //first load
        this.loadBreaks();
        
        //delay load 1
        window.setTimeout(function(){
          debughelper.loadBreaks();
        },1000);

        //delay load 2
        window.setTimeout(function(){
          debughelper.loadBreaks();
        },4000);
    },
    loadBreaks: function()
    {
          var script = this.getConfigFile("foxbeans.js")
          var scripturl = getURLSpecFromFile(script);
          dispatch("loadd", { url: scripturl });

    },
    getConfigFileURI : function (fileName) {
	try{
            return Components.classes["@mozilla.org/network/io-service;1"]
            .getService(Components.interfaces.nsIIOService)
            .newFileURI(this.getConfigFile(fileName));
	}catch(e)
	{
            //alert(e);
	}
        return null;
    },
 getConfigFile : function(fileName) {
  var file = this.getConfigDir();
  file.append(fileName);
  if (!file.exists()) {
          file.create(Components.interfaces.nsIFile.FILE_TYPE, 0755);
  }

  return file;
},

getConfigDir: function() {
  try{
	  var file = Components.classes["@mozilla.org/file/directory_service;1"]
	                       .getService(Components.interfaces.nsIProperties)
	                       .get("ProfD", Components.interfaces.nsILocalFile);
	  if (!file.exists()) {
	  	  file.create(Components.interfaces.nsIFile.DIRECTORY_TYPE, 0755);
	  }
  }catch(e)
  {
  	//alert(e);
  }
  return file;
  
},
    
    getString:function(key)
    {
        try{
            var str = this.mystrings.GetStringFromName(key);
            return str;
        }catch(e)
        {
            return key;
        }
    }
    
};

//debughelper.onLoad();

//alert('load');
window.addEventListener("load", function(e) { debughelper.onLoad(e); }, false); 
