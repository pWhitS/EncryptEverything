/*
Author(s): Fernando Maymi, Patrick Whitsell, Casey McGinley
Course: CS-GY 6903 Applied Cryptography
Instructor: Prof. Giovanni Di Crescenzo
Semester: Spring 2016

Handles the loading and deleting of public and private RSA keys on the "Manage" 
page (import.html) to and from localStorage
*/

var dPublicKey = 1;
var dPrivateKey = 2;

var gKeyType = dPublicKey;

//--- set some constants ---
var EE_KEYLIST = "EE-keyList";
var EE_TIMELIST = "EE-timeList";
var EE_PRIVATE = "EE-Private-Key";
var EE_USER_ID = "EE-User-ID";

// adds an RSA public key and corresponding name/ID to local storage from the 
// key management page
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

// adds an RSA private key and corresponding name/ID to local storage from the 
// key management page; private key is encrypted using AES 256 (sjcl library 
// decrypt routine passes user's password through a PBKDF function)
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

  // encrypt; the password is passed internally though a PBKDF to derive 256 bit 
  // AES key
  var encKey = sjcl.encrypt(password, privKey, params);
  localStorage.setItem(EE_PRIVATE, JSON.stringify(encKey));
  localStorage.setItem(EE_USER_ID, user_id);
  location.reload();
}

// remove public key from local storage
function deletePublicKey() {
  var key = document.getElementById("deleteKey").value;
  var keyList = JSON.parse(localStorage.getItem(EE_KEYLIST));
  delete keyList[key];
  
  localStorage.setItem(EE_KEYLIST, JSON.stringify(keyList));
  location.reload();
}

// setup
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

// registers onclick events
document.addEventListener('DOMContentLoaded', function() {
	init(); //initialize the page
	//document.getElementById("import-pub").onclick = showPublicInputFields;  
	//document.getElementById("import-pri").onclick = showPrivateInputFields;
	document.getElementById("close_window").onclick = close_window;
	document.getElementById("add-priv-key").onclick = addPrivateKey;
	document.getElementById("add-pub-key").onclick = addPublicKey;
	document.getElementById("del-key").onclick = deletePublicKey;
});