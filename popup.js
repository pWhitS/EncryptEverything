

function getSelectedText(callback) {
  var queryInfo = {
    active: true,
    currentWindow: true
  };

  chrome.tabs.executeScript({
    code: "window.getSelection().toString();"
  }, function(selection) {
    //console.log(selection);
    callback(selection);
  });
}

function renderStatus(statusText) {
  document.getElementById('status').textContent = statusText;
}

function openKeyManagerTab() {
  chrome.tabs.create({'url': chrome.extension.getURL('import.html')}, function(tab) {
    //tab code?
  });
}

//--- RSA Encryption Wrappers ---//
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


function decryptSelectedText() {
  //localStorage.setItem("EE-Private-Key", document.getElementById("sec").value);
//  var prikey = localStorage.getItem("EE-Private-Key");
  var prikey = document.getElementById("sec").value; //replace with localStorage

  getSelectedText(function(selectedText) {
    var buf = selectedText.toString();
    var rsaBlock = 172;
    console.log(buf);

    //Selected text must be at least 2 RSA blocks
    if (buf.length < rsaBlock*2) { 
      swal("Error", "No selected text!", "error");
      return;
    }

    //Break up the pieces of encrypted the blob
    var enc_key = buf.substring(0, rsaBlock);
    var enc_iv = buf.substring(rsaBlock, rsaBlock*2);
    var ciphertext_str = buf.substring(rsaBlock*2);
    var ciphertext = sjcl.codec.base64.toBits(ciphertext_str);
    
    //decrypt RSA encrypted AES key and IV
    var aes_key_str = RSADecrypt(enc_key, prikey);
    var iv_str = RSADecrypt(enc_iv, prikey);

    //convert strings to bitArrays for decrypt operation
    var aeskey = sjcl.codec.base64.toBits(aes_key_str);
    var iv = sjcl.codec.base64.toBits(iv_str);
    console.log(aeskey);

    //These are parameters to the decrypt function. 
    //Must match parameters given to encrypt
    var ct_json = {};
    ct_json["cipher"] = "aes";
    ct_json["ct"] = ciphertext;
    ct_json["iter"] = 1000;
    ct_json["iv"] = iv;
    ct_json["ks"] = 256;
    ct_json["v"] = 1;
    ct_json["adata"] = [];
    ct_json["ts"] = 64;
    ct_json["mode"] = "ccm";
    var ct_json_str = sjcl.json.encode(ct_json); //Convert JSON to string

    var plaintext = sjcl.decrypt(aeskey, ct_json_str); //Do the decryption
    if (plaintext == null || plaintext.length == 0) {
      swal("Decryption Error", "Something went wrong...", "error");
      return;
    }
    
    //truncate plaintext that gets displayed in the popup if too big (>150 chars)
    var popup_plaintext = plaintext.substring(0,150) + " ...";

    //Display as popup with options: close, copy to clipboard
    //TODO: Somehow, in copying the plaintext to the clipboard, the newline characters are lost; I suspect this has to do with writing it to the invisibleInputField first; should be fixed
    swal({
      title: "Decryted Text",
      text: popup_plaintext,
      confirmButtonColor: "#DD6B55",
      confirmButtonText: "Copy",
      showCancelButton: true,
      cancelButtonText: "Close",
      closeOnCancel: true,
      closeOnConfirm: true
    },
    function(isCopy) {
      if (isCopy) {
        var invisibleInputField = document.getElementById("invis");
        invisibleInputField.value = plaintext;
        invisibleInputField.focus(); //Moves cursor to textarea
        invisibleInputField.select(); //Selects (Highlights) text in textarea
        document.execCommand("copy");
      }
    });

    console.log(plaintext);
  });
}


//Fucntion encrypts highlighted text
/**
1. Get RSA public key from local storage
2. Generate random string for AES key
3. Get the selected text and encrypt it with AES
4. Encrypt with RSA: (All will be 172 bytes each)
  - AES key
  - IV
5. Append message ciphertext to the end
**/ 
function encryptSelectedText() {  
  var pubkey = document.getElementById("pub").value; //replace with localStorage
  if (pubkey == null || pubkey.length == 0) {
    swal("Error", "No public key found!", "error");
    return;
  }

  var aeskey = sjcl.random.randomWords(8); //8 * 32 == 256 bits
  var aes_key_str = sjcl.codec.base64.fromBits(aeskey);

  getSelectedText(function(selectedText) {
    var buf = selectedText.toString();
    if (buf == null || buf.length == 0) {
      swal("Error", "No text selected!", "error");
      return;
    }

    var params = {};
    params["ks"] = 256; //AES-256 key

    var result_str = sjcl.encrypt(aeskey, buf, params); //do encryption
    var result_obj = sjcl.json.decode(result_str); //get JSON from returned string
    console.log(result_obj);

    var ciphertext = sjcl.codec.base64.fromBits(result_obj.ct); 
    var iv = sjcl.codec.base64.fromBits(result_obj.iv);
    
    //Encrypt AES key and IV with RSA
    var enc_key = RSAEncrypt(aes_key_str, pubkey); //172
    var enc_iv = RSAEncrypt(iv, pubkey); //172

    //Construct the hybrid encrypted message
    var message = "";
    message += enc_key;
    message += enc_iv;
    message += ciphertext;

    console.log("ENCRYPTED KEY: " + enc_key + " LEN: " + enc_key.length);
    console.log("ENCRYPTED IV: " + enc_iv + " LEN: " + enc_iv.length);
    console.log("CIPHERTEXT: " + ciphertext + " LEN: " + ciphertext.length);
    console.log(message);

    //set the invisible element's value to the encrypted message
    var invisibleInputField = document.getElementById("invis");
    invisibleInputField.value = message;

    invisibleInputField.focus(); //Moves cursor to textarea
    invisibleInputField.select(); //Selects (Highlights) text in textarea

    //Copy selected encrypted text from invisible textarea to the clipboard
    document.execCommand("copy"); 

    swal({
      title: "Successful Encryption",
      text: "Ciphertext copied to clipboard",
      timer: 2000,
      showConfirmButton: true
    })
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