
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
//  var prikey = localStorage.getItem("EE-Private-Key");
  var prikey = document.getElementById("sec").value;

  getSelectedText(function(selectedText) {
    var buf = selectedText.toString();
    var rsaBlock = 172;

    if (buf.length < rsaBlock*2) {
      console.log("Error 1");
      return;
    }

    var enc_key = buf.substring(0,rsaBlock);
    var enc_iv = buf.substring(rsaBlock,rsaBlock*2);
    var ciphertext_str = buf.substring(rsaBlock*2);
    var ciphertext = sjcl.codec.base64.toBits(ciphertext_str);
    
    var key_str = RSADecrypt(enc_key, prikey);
    var iv_str = RSADecrypt(enc_iv, prikey);

    var key = sjcl.codec.base64.toBits(key_str);
    var iv = sjcl.codec.base64.toBits(iv_str);
    console.log(key);

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
    console.log(ct_json);

    var ct_json_str = sjcl.json.encode(ct_json);
    var plaintext = sjcl.decrypt(key, ct_json_str);
    console.log(plaintext);
//    var p = RSADecrypt(buf, prikey);
//    
//    if (p == null && buf == "") {
//      swal("Error", "No selected text..", "error");
//    }
//    else if (p != false && p != "" && p != null) {
//      swal({
//        title: "",
//        text: "Decrypted Message",
//        type: "input",
//        inputValue: p,
//        closeOnConfirm: true
//      },
//      function(inval) {
//        return false;
//      });
//    }
//    else {
//      swal("Unable To Decrypt", "Something went wrong...", "error");
//    }

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
  var key = sjcl.random.randomWords(8);
  console.log(key);
  var key_str = sjcl.codec.base64.fromBits(key);

  getSelectedText(function(selectedText) {
    var buf = selectedText.toString();
    var params = {};
    params["ks"] = 256;

    var result_str = sjcl.encrypt(key, buf, params);
    var result_obj = sjcl.json.decode(result_str);
    console.log(result_obj);

    var ciphertext = sjcl.codec.base64.fromBits(result_obj.ct);
    var iv = sjcl.codec.base64.fromBits(result_obj.iv);

    var enc_key = RSAEncrypt(key_str, pubkey); //172
    var enc_iv = RSAEncrypt(iv, pubkey); //172

    console.log("ENCRYPTED KEY: " + enc_key + " LEN: " + enc_key.length);
    console.log("ENCRYPTED IV: " + enc_iv + " LEN: " + enc_iv.length);
    console.log("CIPHERTEXT: " + ciphertext + " LEN: " + ciphertext.length);
    
    var message = "";
    message += enc_key;
    message += enc_iv;
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