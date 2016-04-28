
var dPublicKey = 1;
var dPrivateKey = 2;

var gKeyType = dPublicKey;



function addPubKey(){
  if (localStorage.keyList) {
    //alert(localStorage.getItem("keyList"));
    var keyList = JSON.parse(localStorage.getItem("keyList"));
  } else {
    console.log("No keyList found.  Creating an empty one.")
    var keyList = {};
  }
  var name = document.getElementById("name").value;
  var key = document.getElementById("pubKey").value;
  keyList[name] = key;
  localStorage.setItem("keyList", JSON.stringify(keyList));
  console.log("Added " +name+ " with key "+key+"\nThere are now " + Object.keys(keyList).length + " keys.");
  //alert(JSON.stringify(keyList));
  location.reload()
}

function addPrivKey(){
  var privKey = document.getElementById("privKey").value;
  localStorage.setItem("EE-Private-Key", privKey);
  console.log("Your private key is " + privKey);
}

function delKey(){
  var key = document.getElementById("deleteKey").value;
  var keyList = JSON.parse(localStorage.getItem("keyList"));
  delete keyList[key];
  localStorage.setItem("keyList", JSON.stringify(keyList));
  console.log("Entry for "+key+" has been removed")
  location.reload()
}

function init() {
  //localStorage.removeItem("keyList");
}


function close_window() {
	window.close();
}

function showPublicInputFields() {
	document.getElementById("pubkey-label").style.visibility = "visible";
	document.getElementById("pubkey-name").style.visibility = "visible";
	document.getElementById("rsakey").style.visibility = "visible";
	document.getElementById("rsakey").style.height = "250px";
	gKeyType = dPublicKey;
}


function showPrivateInputFields() {
	document.getElementById("pubkey-label").style.visibility = "hidden";
	document.getElementById("pubkey-name").style.visibility = "collapse";
	document.getElementById("rsakey").style.visibility = "visible";
	document.getElementById("rsakey").style.height = "250px";
	gKeyType = dPrivateKey;
}


document.addEventListener('DOMContentLoaded', function() {
	//document.getElementById("import-pub").onclick = showPublicInputFields;  
	//document.getElementById("import-pri").onclick = showPrivateInputFields;
	document.getElementById("close_window").onclick = close_window;
	document.getElementById("add-priv-key").onclick = addPrivKey;
});