const APP_DISPLAY_NAME = "debughelper";
const APP_NAME = "debughelper";
const APP_PACKAGE = "/informaction/debughelper";
const APP_VERSION = "1.0.1";

const APP_PREFS_FILE="defaults/preferences/debughelper.js";
const APP_XPCOM_SERVICE=null;
const APP_JAR_FILE = "debughelper.jar";
const APP_CONTENT_FOLDER = "content/";
const APP_LOCALES = [
   "en-US"
  ];
  //"it-IT","ja-JP",

const APP_SUCCESS_MESSAGE = APP_DISPLAY_NAME+" should now be available on the statusbar when you restart Mozilla.";

const INST_TO_PROFILE = "Do you wish to install "+APP_DISPLAY_NAME+" to your profile?\nThis will mean it does not need reinstalling when you update Mozilla.\n(Click Cancel if you want "+APP_DISPLAY_NAME+" installing to the Mozilla directory.)";


var instToProfile = true;

myPerformInstall(false);

function myPerformInstall(secondTry) {
  
  var err;
  initInstall(APP_NAME, APP_PACKAGE, APP_VERSION);
  
  if(!secondTry) {  
    // profile installs only work since 2003-03-06
    instToProfile = (buildID>2003030600 && confirm(INST_TO_PROFILE));
  }
  
  var chromef = instToProfile ? getFolder("Profile", "extensions/debughelper@teesoft.info/chrome") : getFolder("chrome");
  err = addFile(APP_PACKAGE, APP_VERSION, "chrome/" + APP_JAR_FILE, chromef, null,true);
  if(APP_PREFS_FILE && (err == SUCCESS) ) {
    const prefDirs=[
      getFolder("Profile","pref"),
      getFolder(getFolder(getFolder("Program"),"defaults"),"pref")
      ];
    for(var j=prefDirs.length; j-->0;) {
      var prefDir=prefDirs[j];
      
      err = addFile(APP_PACKAGE, APP_VERSION,  APP_PREFS_FILE, prefDir, null, true);
      logComment("Adding "+APP_PREFS_FILE+" in "+prefDir+": exit code = "+err);
    }
  }
      if(APP_XPCOM_SERVICE) {
      var componentsDir = getFolder("Components");
      addFile(APP_PACKAGE,APP_VERSION, APP_XPCOM_SERVICE, componentsDir, null, true);
      addFile(APP_NAME, "components/.autoreg", getFolder("Program"), "");
    }
    
  if(err == SUCCESS) {
    var jar =  getFolder(chromef, APP_JAR_FILE);
    
    const chromeFlag=instToProfile?PROFILE_CHROME:DELAYED_CHROME;
  
    registerChrome(CONTENT | chromeFlag, jar, APP_CONTENT_FOLDER);//'jar, APP_CONTENT_FOLDER);
    
    var localesCount=APP_LOCALES.length;
    if(localesCount>0) {
      registerChrome(LOCALE | chromeFlag,  jar,"locale/"+APP_LOCALES[--localesCount]+"/");
      while(localesCount-- >0) {
        registerChrome(LOCALE  | chromeFlag,  jar,"locale/"+APP_LOCALES[localesCount]+"/");
      }
    }
    performInstall();
    initInstall(APP_NAME, APP_PACKAGE, APP_VERSION);
        
    registerChrome(SKIN | chromeFlag, jar ,"skin/");

    err = performInstall();
    if(err == -239 && !secondTry) {
      alert("Chrome registration problem, maybe transient, you can try restart to see it works or not.");
      cancelInstall(err);
      myPerformInstall(true);
      return;
    }
    if(err == SUCCESS || err == 999) {
      alert(APP_DISPLAY_NAME+" "+APP_VERSION+" has been succesfully installed.\n"+APP_SUCCESS_MESSAGE);
    } else {
      var msg = "Install failed!!! Error code:" + err;

      if(err == -239) {
        msg += "\nThis specific error is usually transient:"
          +"\nif you retry to install again, it will probably go away."
      }

      alert(msg);
      //cancelInstall(err);
    }
  } else {
    alert("Failed to create " +APP_JAR_FILE +"\n"
      +"You probably don't have appropriate permissions \n"
      +"(write access to your profile or chrome directory). \n"
      +"_____________________________\nError code:" + err);
    cancelInstall(err);
  }
}
