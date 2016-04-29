

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
  var prikey = localStorage.getItem("EE-Private-Key");

  getSelectedText(function(selectedText) {
    // sanity check that the user has uploaded their private key
    if (prikey == null || prikey.length == 0) {
      swal("Error", "No private key found", "error");
      return;
    }
    var buf = selectedText.toString();

    //Selected text must be at least 2 RSA blocks
    if (buf.length < G_RSA_BLOCK_SIZE*2) { 
      swal("Error", "No selected text!", "error");
      return;
    }
    
    // grab the digital signature from the encrypted blob
    var digital_signature = buf.substring(0, G_RSA_BLOCK_SIZE);
    var enc_sender_id = buf.substring(G_RSA_BLOCK_SIZE, G_RSA_BLOCK_SIZE*2);
    
    // Decrypt the sender_id with the recipient's private jey
    var sender_id = RSADecrypt(enc_sender_id, prikey);
    
    // Check if decryption failed
    // TODO allow the user to bypass if just decrypting sender_id fails
    if (sender_id == null) {
      swal("Decryption Failed", "The message could not be decrypted", "error");
      return;
    }
    
    // get public key of sender
    var pubkey = localStorage.getItem(sender_id);
    
    // check if we have the sender's public key
    // TODO allow the user to bypass the integrity/auth check if desired
    if (pubkey == null || pubkey.length == 0) {
      swal("Error", "No public key found for the following ID: " + sender_id, "error");
      return;
    }
    
    // decrypt the signature using the sender's public RSA key to get the hash calculated by the sender
    var received_message_digest_str = RSAVerify(digital_signature, pubkey);
    var received_message_digest = sjcl.codec.hex.toBits(received_message_digest_str);
    
    // calculate a hash directly on the message
    var message = buf.substring(G_RSA_BLOCK_SIZE);
    var calculated_message_digest = sjcl.hash.sha256.hash(message);
    
    
    // if digests are not equal, then the message is either not authentic or it was modified in transit
    if (!(digestsAreEqual(calculated_message_digest, received_message_digest))) {
      console.log("Bad digest");
      //Display as popup window reporting failed integrity/auth check
      swal("Error","Message failed integrity/authenticity checks. Could not verify signature of sender.","error");
      return;
    }
    // if we pass the previous if-block, digests are equal, authenticity and integrity has been verified
    console.log("Equal digests");
    
    //Break up the rest of the pieces of encrypted data from the message blob
    var enc_key = message.substring(G_RSA_BLOCK_SIZE, G_RSA_BLOCK_SIZE*2);
    var enc_iv = message.substring(G_RSA_BLOCK_SIZE*2, G_RSA_BLOCK_SIZE*3);
    var ciphertext_str = message.substring(G_RSA_BLOCK_SIZE*3);

    //decrypt AES key and IV using recipient's RSA private key
    var aes_key_str = RSADecrypt(enc_key, prikey);
    var iv_str = RSADecrypt(enc_iv, prikey);

    //Check if decryption failed
    if (aes_key_str == null || iv_str == null) {
      swal("Decryption Failed", "The message could not be decrypted", "error");
      return;
    }
    
    //convert strings to bitArrays for decrypt operation
    var aeskey = sjcl.codec.base64.toBits(aes_key_str);
    var iv = sjcl.codec.base64.toBits(iv_str);
    var ciphertext = sjcl.codec.base64.toBits(ciphertext_str);

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
      title: "Decrypted Text",
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
function encryptSelectedText(sender_id, pubkey) {  
  if (pubkey == null || pubkey.length == 0) {
    swal("Error", "No public key found for the following ID: " + sender_id, "error");
    return;
  }
  // get private key for signing
  var prikey = localStorage.getItem("EE-Private-Key");

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
    
    // generate a hash of the hybrid encrypted message
    var message_digest = sjcl.hash.sha256.hash(message);
    var message_digest_str = sjcl.codec.hex.fromBits(message_digest);
    
    // encrypt the hash with sender's private key to generate a digital signature (integrity, authenticity)
    var digital_signature = RSASign(message_digest_str, prikey);
    
    console.log("DIGITAL SIGNATURE: " + digital_signature + " LEN: " + digital_signature.length);
    
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

//Puts the public keys into the select list
function showPublicKeys() {
  var selectDiv = document.getElementById("invis-select");
  var select = document.getElementById("public-key-select");
  var buttons = document.getElementById("buttons");

  //get the keylist from localStorage
  var keyList = JSON.parse(localStorage.getItem("keyList"));
  if (keyList == null) {
    swal("Error", "No public keys...", "error");
    return;
  }
  var keys = Object.keys(keyList); //get only the keys from the public key dictionary

  buttons.style.visibility = "hidden"; //hide main menu buttons
  selectDiv.style.visibility = "visible"; //show the select public key form
  
  //reset the select list
  select.options.length = 0; 
  var blankOption = document.createElement("option");
  blankOption.textContent = "Select Public Key"; 
  blankOption.value = "NONE";
  select.appendChild(blankOption); 

  //populate the select list with public key names
  for (var i=0; i < keys.length; i++) {
    var opt = keys[i]; 
    var el = document.createElement("option");
    el.textContent = opt;
    el.value = opt;
    select.appendChild(el);
  }
}

//Gets the selected public key and uses it for encryption.
//Returns to the main menu
function selectPublicKey() {
  var keyname = document.getElementById("public-key-select").value;
  if (keyname == "NONE") {
    return;
  }
  var keyList = JSON.parse(localStorage.getItem("keyList"));
  var key = keyList[keyname]; 

  encryptSelectedText(keyname, key); //call encryption routine with key name
  closeKeySelect(); //resets the display
}

//Hids the public key select form
//Returns the main menu to visible
function closeKeySelect() {
  document.getElementById("invis-select").style.visibility = "hidden";
  document.getElementById("buttons").style.visibility = "visible";
}


//Assumes ciphertext structure:
/*
344 - AES key
344 - AES IV
XXX - Message
344 - Signature over sha256
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

  document.getElementById("encrypt").onclick = showPublicKeys;
  document.getElementById("pubkey-button-select").onclick = selectPublicKey;
  document.getElementById("pubkey-button-cancel").onclick = closeKeySelect;

  document.getElementById("verify").onclick = verifySelectedtext;

  //renderStatus("Initializing......");

  // var keygen = new JSEncrypt({default_key_size: 1024});
  // keygen.getKey();
  // prikey = keygen.getPrivateKey();
  // pubkey = keygen.getPublicKey();
  
});