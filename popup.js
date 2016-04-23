
function RSAEncrypt(buffer, pubkey) {
  var enc = new JSEncrypt();
  enc.setPublicKey(pubkey);
  var ciphertext = enc.encrypt(buffer);
  return ciphertext;
}

function RSADecrypt(buffer, prikey) {
  var dec = new JSEncrypt();
  dec.setPrivateKey(prikey);
  var plaintext = dec.decrypt(buffer);
  return plaintext;
}

function getSelectedText(callback) {
  var queryInfo = {
    active: true,
    currentWindow: true
  };

  chrome.tabs.executeScript({
    code: "window.getSelection().toString();"
  }, function(selection) {
    callback(selection);
  });
}

function renderStatus(statusText) {
  document.getElementById('status').textContent = statusText;
}

function openKeyManagerTab() {
  chrome.tabs.create({'url': chrome.extension.getURL('import.html')}, function(tab) {
    //tab?
  });
}

function decryptSelectedText() {
  //localStorage.setItem("EE-Private-Key", document.getElementById("sec").value);
  var prikey = localStorage.getItem("EE-Private-Key");


  getSelectedText(function(selectedText) {
    var buf = selectedText.toString();    
    var p = RSADecrypt(buf, prikey);
    
    if (p == null && buf == "") {
      swal("Error", "No selected text..", "error");
    }
    else if (p != false && p != "" && p != null) {
      swal({
        title: "",
        text: "Decrypted Message",
        type: "input",
        inputValue: p,
        closeOnConfirm: true
      },
      function(inval) {
        return false;
      });
    }
    else {
      swal("Unable To Decrypt", "Something went wrong...", "error");
    }

  });
}


function createRandomString(length) {
  var arr = new Uint32Array(parseInt(length));
  window.crypto.getRandomValues(arr);
  var str = ""

  for (var i=0; i < arr.length; ++i) {
    str += String.fromCharCode(arr[i] % 128);
  }

  return window.btoa(str);
}


//Fucntion encrypts highlighted text
/**
1. Get RSA public key from local storage
2. Generate random string (password) for PBKDF2
3. Get the selected text and encrypt it with AES
4. Encrypt with RSA:
  - password
  - IV
  - random salt
5. Append message ciphertext to the end
**/ 
function encryptSelectedText() {  
  var pubkey = document.getElementById("pub").value;
  var password = createRandomString(30); 

  getSelectedText(function(selectedText) {
    var buf = selectedText.toString();
    var ct = sjcl.encrypt(password, buf);

    var ciphertext = ct.match(/"ct":"([^"]*)"/)[1];
    var iv = ct.match(/"iv":"([^"]*)"/)[1];
    var salt = ct.match(/"salt":"([^"]*)"/)[1];

    var message = RSAEncrypt(password, pubkey); //172
    message += RSAEncrypt(iv, pubkey) //172
    message += RSAEncrypt(salt, pubkey) //172
    message += ciphertext;

    console.log(message);
  });
}


document.addEventListener('DOMContentLoaded', function() {
  document.getElementById("import").onclick = openKeyManagerTab;
  document.getElementById("decrypt").onclick = decryptSelectedText;
  document.getElementById("encrypt").onclick = encryptSelectedText;

  renderStatus("Initializing......");

  // var keygen = new JSEncrypt({default_key_size: 1024});
  // keygen.getKey();
  // prikey = keygen.getPrivateKey();
  // pubkey = keygen.getPublicKey();
  
});