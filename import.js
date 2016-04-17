
var dPublicKey = 1;
var dPrivateKey = 2;

var gKeyType = dPublicKey;


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
});