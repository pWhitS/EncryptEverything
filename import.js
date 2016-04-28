
var dPublicKey = 1;
var dPrivateKey = 2;

var gKeyType = dPublicKey;



function addPublicKey() {
  if (localStorage.keyList) {
    //alert(localStorage.getItem("keyList"));
    var keyList = JSON.parse(localStorage.getItem("keyList"));
  } 
  else {
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

function addPrivateKey() {
  var privKey = document.getElementById("privKey").value;
  localStorage.setItem("EE-Private-Key", privKey);
  console.log("Your private key is " + privKey);
}

function deletePublicKey() {
  var key = document.getElementById("deleteKey").value;
  var keyList = JSON.parse(localStorage.getItem("keyList"));
  delete keyList[key];
  console.log("Entry for "+key+" has been removed")

  localStorage.setItem("keyList", JSON.stringify(keyList));
  location.reload()
}

function init() {
  	//localStorage.removeItem("keyList");
  	var select = document.getElementById("deleteKey");
	var keyList = JSON.parse(localStorage.getItem("keyList"));
	if (keyList == null) {
		return;
	}
	var keys = Object.keys(keyList);

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