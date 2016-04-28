

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
  var ciphertext = enc.encrypt(buffer,false);
  return ciphertext;
}

function RSADecrypt(buffer, prikey) {
  var dec = new JSEncrypt();
  dec.setPrivateKey(prikey);
  var plaintext = dec.decrypt(buffer,false);
  return plaintext;
}

//--- RSA Signature Wrappers ---//
function RSASign(digest, prikey) {
  var enc = new JSEncrypt();
  enc.setPrivateKey(prikey);
  var signature = enc.encrypt(digest,true);
  return signature;
}

function RSAVerify(signature, pubkey) {
  var dec = new JSEncrypt()
  dec.setPublicKey(pubkey);
  var digest = dec.decrypt(signature,true);
  return digest;
}

// takes two digests as bitArrays (from sjcl) and compares the value by value to determine equality
function digestsAreEqual(digest1, digest2) {
  if (digest1.length != digest2.length) {
    return false;
  }
  for (i = 0; i < digest1.length; i++) {
    if (digest1[i] != digest2[i]) {
      return false;
    }
  }
  return true;
}

var G_RSA_BLOCK_SIZE = 344; //scales linearly with key size. 2048 key - 344

//Fucntion decrypts highlighted text
/**
1. Get RSA private key from local storage
2. Decrypt AES key and IV
3. Decrypt AES ciphertext
4. Display text to user, allow copy to clipboard
**/
function decryptSelectedText() {
  //localStorage.setItem("EE-Private-Key", document.getElementById("sec").value);
//  var prikey = localStorage.getItem("EE-Private-Key");
  var prikey = document.getElementById("sec").value; //replace with localStorage
  var pubkey = document.getElementById("pub").value; //replace with localStorage

  getSelectedText(function(selectedText) {
    var buf = selectedText.toString();
    console.log(buf);

    //Selected text must be at least 2 RSA blocks
    if (buf.length < G_RSA_BLOCK_SIZE*2) { 
      swal("Error", "No selected text!", "error");
      return;
    }
    
    // grab the digital signature from the encrypted blob
    var digital_signature = buf.substring(0, G_RSA_BLOCK_SIZE);
    console.log(digital_signature);
    
    // decrypt the signature using the sender's public RSA key to get the hash calculated by the sender
    var received_message_digest_str = RSAVerify(digital_signature, pubkey);
    console.log(received_message_digest_str);
    var received_message_digest = sjcl.codec.hex.toBits(received_message_digest_str);
    
    // calculate a hash directly on the message
    var message = buf.substring(G_RSA_BLOCK_SIZE);
    console.log("MESSAGE: " + message + " LEN: " + message.length);
    console.log(typeof(message));
    var calculated_message_digest = sjcl.hash.sha256.hash(message);
    
    if (digestsAreEqual(calculated_message_digest, received_message_digest)) {
      //Break up the rest of the pieces of encrypted data from the message blob
      var enc_sender_id = message.substring(0, G_RSA_BLOCK_SIZE);
      var enc_key = message.substring(G_RSA_BLOCK_SIZE, G_RSA_BLOCK_SIZE*2);
      var enc_iv = message.substring(G_RSA_BLOCK_SIZE*2, G_RSA_BLOCK_SIZE*3);
      var ciphertext_str = message.substring(G_RSA_BLOCK_SIZE*3);
      var ciphertext = sjcl.codec.base64.toBits(ciphertext_str);

      //decrypt sender ID (e.g. email), AES key, and IV using recipient's RSA private key
      var sender_id = RSADecrypt(enc_sender_id, prikey);
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
      if (plaintext.length > 150) {
        var popup_plaintext = plaintext.substring(0,150) + " ...";
      } else {
        var popup_plaintext = plaintext;
      }

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
    } else {
      //Display as popup window reporting failed integrity/auth check
      swal({
        title: "Integrity/Authenticity Error",
        text: "Message failed integrity/authenticity checks. Could not verify signature of sender.",
        showCancelButton: true,
        cancelButtonText: "Close",
        closeOnCancel: true,
      });
    }
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
  var prikey = document.getElementById("sec").value; //replace with localStorage
  var sender_id = "myemail@somedomain.com"; //replace with localStorage
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
    //params["mode"] = "ctr";

    var result_str = sjcl.encrypt(aeskey, buf, params); //do encryption
    var result_obj = sjcl.json.decode(result_str); //get JSON from returned string
    console.log(result_obj);

    var ciphertext = sjcl.codec.base64.fromBits(result_obj.ct); 
    var iv = sjcl.codec.base64.fromBits(result_obj.iv);
    
    //Encrypt sender ID (e.g. email), AES key, and IV with RSA using public key of recipient
    var enc_sender_id = RSAEncrypt(sender_id, pubkey);
    var enc_key = RSAEncrypt(aes_key_str, pubkey); //172
    var enc_iv = RSAEncrypt(iv, pubkey); //172

    //Construct the hybrid encrypted message
    var message = "";
    message += enc_sender_id;
    message += enc_key;
    message += enc_iv;
    message += ciphertext;

    console.log("ENCRYPTED ID: " + enc_sender_id + " LEN: " + enc_sender_id.length);
    console.log("ENCRYPTED KEY: " + enc_key + " LEN: " + enc_key.length);
    console.log("ENCRYPTED IV: " + enc_iv + " LEN: " + enc_iv.length);
    console.log("CIPHERTEXT: " + ciphertext + " LEN: " + ciphertext.length);
    console.log(message);
    
    // generate a hash of the hybrid encrypted message
    console.log("MESSAGE: " + message + " LEN: " + message.length);
    console.log(typeof(message));
    var message_digest = sjcl.hash.sha256.hash(message);
    var message_digest_str = sjcl.codec.hex.fromBits(message_digest);
    
    console.log("MESSAGE DIGEST RAW: " + message_digest + " LEN: " + message_digest.length);
    console.log("MESSAGE DIGEST HEX: " + message_digest_str + " LEN: " + message_digest_str.length);    
    
    // encrypt the hash with sender's private key to generate a digital signature (integrity, authenticity)
    var digital_signature = RSASign(message_digest_str, prikey);
    
    console.log("DIGITAL SIGNATURE: " + digital_signature + " LEN: " + digital_signature.length);
    console.log(RSAVerify(digital_signature,pubkey))
//    var test1 = new JSEncrypt();
//    test1.setPrivateKey(prikey);
//    var test_sig = test1.encrypt(message_digest_str);
//    console.log(test_sig);
//    var test2 = new JSEncrypt();
//    test2.setPublicKey(pubkey);
//    console.log(test2.decrypt(test_sig));
    
    // prepend the signature to the message to sign it
    var signed_message = digital_signature + message;

    //set the invisible element's value to the encrypted message
    var invisibleInputField = document.getElementById("invis");
    invisibleInputField.value = signed_message;

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


//Assumes ciphertext structure:
/*
172 - AES key
172 - AES IV
XXX - Message
172 - Signature of sha256
*/

function verifySelectedtext() {
  var pubkey = document.getElementById("pub").value; //replace with localStorage
  if (pubkey == null || pubkey.length == 0) {
    swal("Error", "No public key found!", "error");
    return;
  }

  getSelectedText(function(selectedText) {
    var buf = selectedText.toString();
    var clength = buf.length;
    // if (buf == null || clength == 0) {
    //   swal("Error", "No text selected!", "error");
    //   return;
    // }

    var signature = buf.substring(clength - G_RSA_BLOCK_SIZE);
    var ciphertext = buf.substring(0, clength - G_RSA_BLOCK_SIZE)

    var sig_hash = RSADecrypt(signature, pubkey);
    var verify_hash = sjcl.hash.sha256.hash(ciphertext);
    verify_hash = sjcl.codec.base64.fromBits(verify_hash);

    console.log("SIG: " + signature);
    console.log("CIPHERTEXT: " + ciphertext);
    console.log(sig_hash + " -- " + verify_hash);

    if (sig_hash == verify_hash) {
      swal({
        title: "Verified!",
        text: "",
        timer: 2000,
        showConfirmButton: true
      });
    }
    else {
      swal({
        title: "Verification Failed!",
        text: "Message is from an untrusted sender",
        showConfirmButton: true,
        type: "error"
      });
    }
  });
}

document.addEventListener('DOMContentLoaded', function() {
  document.getElementById("import").onclick = openKeyManagerTab;
  document.getElementById("decrypt").onclick = decryptSelectedText;
  document.getElementById("encrypt").onclick = encryptSelectedText;
  document.getElementById("verify").onclick = verifySelectedtext;

  //renderStatus("Initializing......");

  // var keygen = new JSEncrypt({default_key_size: 1024});
  // keygen.getKey();
  // prikey = keygen.getPrivateKey();
  // pubkey = keygen.getPublicKey();
  
});