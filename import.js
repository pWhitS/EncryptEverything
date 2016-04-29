var dPublicKey = 1;
var dPrivateKey = 2;

var gKeyType = dPublicKey;

//--- set some constants ---
var EE_KEYLIST = "EE-keyList";
var EE_TIMELIST = "EE-timeList";
var EE_PRIVATE = "EE-Private-Key";
var EE_USER_ID = "EE-User-ID";

function addPublicKey() {
  var keyList = {};
  if (localStorage.getItem(EE_KEYLIST) != null) {
      keyList = JSON.parse(localStorage.getItem(EE_KEYLIST));
  } 

  var name = document.getElementById("pub-name").value;
  name = name.trim();
  var key = document.getElementById("pubKey").value;
  key = key.trim();
  keyList[name] = key;
  localStorage.setItem(EE_KEYLIST, JSON.stringify(keyList));
  location.reload();
}

function addPrivateKey() {
  var privKey = document.getElementById("privKey").value;
  privKey = privKey.trim();
  var password = document.getElementById("password").value;
  password = password.trim();
  var user_id = document.getElementById("pri-name").value;
  user_id = user_id.trim();
  
  //setting AES key size
  var params = {};
  params["ks"] = 256; //AES-256 key
  var encKey = sjcl.encrypt(password, privKey, params);
  localStorage.setItem(EE_PRIVATE, JSON.stringify(encKey));
  localStorage.setItem(EE_USER_ID, user_id);
  location.reload();
}

function deletePublicKey() {
  var key = document.getElementById("deleteKey").value;
  var keyList = JSON.parse(localStorage.getItem(EE_KEYLIST));
  delete keyList[key];
  console.log("Entry for "+key+" has been removed");
  
  localStorage.setItem(EE_KEYLIST, JSON.stringify(keyList));
  location.reload();
}

function init() {
  if (localStorage.getItem(EE_KEYLIST) === null) {
    return;
  }
  var keyList = JSON.parse(localStorage.getItem(EE_KEYLIST));
  var keys = Object.keys(keyList);

  var select = document.getElementById("deleteKey");
  for (var i=0; i < keys.length; i++) {
    var opt = keys[i]; 
    var el = document.createElement("option");
    el.textContent = opt;
    el.value = opt;
    select.appendChild(el);
  }
}

//Closes the manager window
function close_window() {
    window.close();
}

//THIS ARE CURRENTLY NOT IN USE
function showPublicInputFields() {
    document.getElementById("pubkey-label").style.visibility = "visible";
    document.getElementById("pubkey-name").style.visibility = "visible";
    document.getElementById("rsakey").style.visibility = "visible";
    document.getElementById("rsakey").style.height = "250px";
    gKeyType = dPublicKey;
}

//THIS ARE CURRENTLY NOT IN USE
function showPrivateInputFields() {
    document.getElementById("pubkey-label").style.visibility = "hidden";
    document.getElementById("pubkey-name").style.visibility = "collapse";
    document.getElementById("rsakey").style.visibility = "visible";
    document.getElementById("rsakey").style.height = "250px";
    gKeyType = dPrivateKey;
}


document.addEventListener('DOMContentLoaded', function() {
	init(); //initialize the page
	//document.getElementById("import-pub").onclick = showPublicInputFields;  
	//document.getElementById("import-pri").onclick = showPrivateInputFields;
	document.getElementById("close_window").onclick = close_window;
	document.getElementById("add-priv-key").onclick = addPrivateKey;
	document.getElementById("add-pub-key").onclick = addPublicKey;
	document.getElementById("del-key").onclick = deletePublicKey;
});