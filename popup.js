
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

document.addEventListener('DOMContentLoaded', function() {
  renderStatus("Initializing......");

  var keygen = new JSEncrypt({default_key_size: 1024});

  keygen.getKey();
  prikey = keygen.getPrivateKey();
  pubkey = keygen.getPublicKey();
  
  getSelectedText(function(selectedText) {
    var buf = selectedText.toString();    

  });
});