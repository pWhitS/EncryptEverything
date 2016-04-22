
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
  var prikey = document.getElementById("sec").value;

  getSelectedText(function(selectedText) {
    var buf = selectedText.toString();    
    var p = RSADecrypt(buf, prikey);
    
    if (p != false && p != "" && p != null) {
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


document.addEventListener('DOMContentLoaded', function() {
  document.getElementById("import").onclick = openKeyManagerTab;
  document.getElementById("decrypt").onclick = decryptSelectedText;

  renderStatus("Initializing......");

  // var keygen = new JSEncrypt({default_key_size: 1024});
  // keygen.getKey();
  // prikey = keygen.getPrivateKey();
  // pubkey = keygen.getPublicKey();
  
});