var dPublicKey = 1;
var dPrivateKey = 2;

var gKeyType = dPublicKey;



function addPublicKey() {
  var keyList = {};
  if (localStorage.getItem("EE-keyList") != null) {
      keyList = JSON.parse(localStorage.getItem("EE-keyList"));
  } 

  var name = document.getElementById("name").value;
  var key = document.getElementById("pubKey").value;
  keyList[name] = key;
  localStorage.setItem("EE-keyList", JSON.stringify(keyList));
  location.reload();
}

function addPrivateKey() {
  var privKey = document.getElementById("privKey").value;
  var password = document.getElementById("password").value;
  var encKey = sjcl.encrypt(password, privKey);
  localStorage.setItem("EE-Private-Key", JSON.stringify(encKey));
  location.reload();
}

function deletePublicKey() {
  var key = document.getElementById("deleteKey").value;
  var keyList = JSON.parse(localStorage.getItem("EE-keyList"));
  delete keyList[key];
  console.log("Entry for "+key+" has been removed");
  
  localStorage.setItem("EE-keyList", JSON.stringify(keyList));
  location.reload();
}

function init() {
  if (localStorage.getItem("EE-keyList") === null) {
    return;
  }
  var keyList = JSON.parse(localStorage.getItem("EE-keyList"));
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