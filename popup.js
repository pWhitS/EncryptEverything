/*
Author(s): Casey McGinley, Patrick Whitsell, Fernando Maymi
Course: CS-GY 6903 Applied Cryptography
Instructor: Prof. Giovanni Di Crescenzo
Semester: Spring 2016

The core program logic. Hooks callbacks on button presses, as well as 
performing encryption, decryption, signing, verifying, and timestamping on 
supplied messages.
*/

// Grabs currently highlighted text
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

// Opens a new tab; used to open our RSA key management screen
function openKeyManagerTab() {
  chrome.tabs.create({'url': chrome.extension.getURL('import.html')}, function(tab) {
    //tab code?
  });
}

//--- RSA Encryption Wrappers ---//
// Wraps the JSEncrypt encrypt function; should only be used with public keys
function RSAEncrypt(buffer, pubkey) {
  var enc = new JSEncrypt();
  enc.setPublicKey(pubkey);
  var ciphertext = enc.encrypt(buffer,false);
  return ciphertext;
}
// Wraps the JSEncrypt decrypt function; should only be used with private keys
function RSADecrypt(buffer, prikey) {
  var dec = new JSEncrypt();
  dec.setPrivateKey(prikey);
  var plaintext = dec.decrypt(buffer,false);
  return plaintext;
}

//--- RSA Signature Wrappers ---//
// Wraps the JSEncrypt encrypt function and passes a special argument in order
// to trigger the portion of JSEncrypt we modified. This allows us to encrypt
// with a private key (JSEncrypt support encryption by public key only by 
// default) for the purpose of signing.
function RSASign(digest, prikey) {
  var enc = new JSEncrypt();
  enc.setPrivateKey(prikey);
  var signature = enc.encrypt(digest,true);
  return signature;
}
// Wraps the JSEncrypt decrypt function, but calls the modified code to allow 
// us to decrypt with a public key in order to verfiy a signature.
function RSAVerify(signature, pubkey) {
  var dec = new JSEncrypt()
  dec.setPublicKey(pubkey);
  var digest = dec.decrypt(signature,true);
  return digest;
}

// Takes two digests as bitArrays (from sjcl) and compares the value by value 
// to determine equality. Returns a Boolean
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

// Grabs timestamps from localStorage using sender_id as key; returns null if 
// no previous timestamp for sender_id
function getPrevTimestamp(sender_id) {
  var timelist_str = localStorage.getItem(EE_TIMELIST);
  if (timelist_str == null) {
    return null;
  }
  var timelist = JSON.parse(timelist_str);
  if (sender_id in timelist) {
    return parseInt(timelist[sender_id]);
  }
  return null;
}

// Updates timestamp of most recent message from sender_id to storage
function updateTimestamp(timestamp, sender_id) {
  var timelist_str = localStorage.getItem(EE_TIMELIST);
  var timelist = null;
  if (timelist_str == null) {
    timelist = {};
  } else {
    timelist = JSON.parse(timelist_str);
  }
  timelist[sender_id] = timestamp.toString();
  localStorage.setItem(EE_TIMELIST, JSON.stringify(timelist));
}

//--- set some constants ---
var G_RSA_BLOCK_SIZE = 344; //scales linearly with key size. 2048 key - 344
var EE_KEYLIST = "EE-keyList";
var EE_TIMELIST = "EE-timeList";
var EE_PRIVATE = "EE-Private-Key";
var EE_USER_ID = "EE-User-ID";

//Fucntion decrypts highlighted text
/**
1. Get RSA private key from local storage
2. Decrypt sender ID 
3. Get RSA public key of sender from local storage using ID
4. Use public key to verify the digital signature (signed hash)
5. Decrypt timestamp and check if message is stale (e.g. replay attack)
6. Decrypt AES key and IV
7. Decrypt AES ciphertext
8. Display text to user, allow copy to clipboard
**/
function decryptSelectedText() {
  // Prompt the user for their password
  swal({
    title: "Password",
    text: "Please provide the password you used to encrypt your private key",
    type: "input",
    showCancelButton: true,
    closeOnConfirm: false,
  },
  function(inputValue){
    // do nothing on cancel
    if (inputValue === false) {
      return false;
    }
    // attempt decryption with provided password
    decryptSubroutine(inputValue);
  });
}

// Subroutine for decryption separated for the purpose of readbility
function decryptSubroutine(pwd) {
  // get private key for signing
  var enc_prikey_str = localStorage.getItem(EE_PRIVATE);
  var enc_prikey = JSON.parse(enc_prikey_str);

  // attempt to decrypt private key and report if password is invalid
  var prikey = null;
  try {
    prikey = sjcl.decrypt(pwd, enc_prikey);
  } catch(ex) {
    invalidPassword();
    return;
  }
  if (prikey == null) {
    invalidPassword();
    return;
  }

  // grab the highlighted text and perform decryption
  getSelectedText(function(selectedText) {
    // sanity check that the user has uploaded their private key
    if (prikey == null || prikey.length == 0) {
      swal("Error", "No private key found", "error");
      return;
    }
    
    // grab the selected text
    var buf = selectedText.toString();

    //check for no text selected
    if (buf.length == 0 || buf == null) { 
      swal("Error", "No text selected!", "error");
      return;
    }

    // remove whitespace; helps with leading/trailing whitespace as well as 
    // unintentional new lines introduced by text editors
    buf = buf.replace(/\s/g, "");

    //Selected text must be at least 5 RSA blocks
    if (buf.length < G_RSA_BLOCK_SIZE*5) { 
      swal("Error", "Invalid ciphertext!", "error");
      return;
    }
    
    // grab the digital signature and the encrypted sender ID from the 
    // encrypted blob
    var digital_signature = buf.substring(0, G_RSA_BLOCK_SIZE);
    var enc_sender_id = buf.substring(G_RSA_BLOCK_SIZE, G_RSA_BLOCK_SIZE*2);
    
    // Decrypt the sender_id with the recipient's private jey
    var sender_id = RSADecrypt(enc_sender_id, prikey);
    
    // Check if decryption failed
    if (sender_id == null || sender_id == false) {
      swal("Decryption Failed", "The message could not be decrypted", "error");
      return;
    }
    
    // get public key of sender
    var keylist = JSON.parse(localStorage.getItem(EE_KEYLIST));
    var pubkey = keylist[sender_id];
    
    // check if we have the sender's public key
    if (pubkey == null || pubkey.length == 0) {
      swal("Error", "No public key found for the following ID: " + sender_id, "error");
      return;
    }
    
    // decrypt the signature using the sender's public RSA key to get the hash 
    // calculated by the sender
    var received_message_digest_str = RSAVerify(digital_signature, pubkey);

    // check if verification was a success
    if (received_message_digest_str == null || received_message_digest_str == false) {
      swal("Verification Failed", "The signature could not be authenticated", "error");
      return;
    }

    // convert digest to bit representation
    var received_message_digest = sjcl.codec.hex.toBits(received_message_digest_str);
    
    // calculate our own hash directly on the message
    var message = buf.substring(G_RSA_BLOCK_SIZE);
    var calculated_message_digest = sjcl.hash.sha256.hash(message);

    // if digests are not equal, then the message is either not authentic or it 
    // was modified in transit; if so, we report to the user and end the 
    // decryption attempt
    if (!(digestsAreEqual(calculated_message_digest, received_message_digest))) {
      swal("Error","Message failed integrity/authenticity checks. Could not verify signature of sender.","error");
      return;
    }
    
    // decrypt timestamp
    var enc_timestamp_str = buf.substring(G_RSA_BLOCK_SIZE*2, G_RSA_BLOCK_SIZE*3);
    var timestamp_str = RSADecrypt(enc_timestamp_str, prikey);
    
    // Check if decryption failed
    if (timestamp_str == null || timestamp_str == false) {
      swal("Decryption Failed", "The message could not be decrypted", "error");
      return;
    }
    
    //check that timestamp is not stale; it must be newer than the previous 
    // timestamp seen from the given sender
    var timestamp = parseInt(timestamp_str);
    var prev_timestamp = getPrevTimestamp(sender_id);
    if (timestamp <= prev_timestamp) {
      swal("Error","Stale timestamp, possible replay attack","error");
      return;
    }
    
    //Break up the rest of the pieces of encrypted data from the message blob
    var enc_key = buf.substring(G_RSA_BLOCK_SIZE*3, G_RSA_BLOCK_SIZE*4);
    var enc_iv = buf.substring(G_RSA_BLOCK_SIZE*4, G_RSA_BLOCK_SIZE*5);
    var ciphertext_str = buf.substring(G_RSA_BLOCK_SIZE*5);

    //decrypt AES key and IV using recipient's RSA private key
    var aes_key_str = RSADecrypt(enc_key, prikey);
    var iv_str = RSADecrypt(enc_iv, prikey);

    //Check if decryption failed
    if (aes_key_str == null || iv_str == null || aes_key_str == false || iv_str == null) {
      swal("Decryption Failed", "The message could not be decrypted", "error");
      return;
    }
    
    //convert strings to bitArrays for decrypt operation
    var aeskey = sjcl.codec.base64.toBits(aes_key_str);
    var iv = sjcl.codec.base64.toBits(iv_str);
    var ciphertext = sjcl.codec.base64.toBits(ciphertext_str);

    // These are parameters to the decrypt function. 
    // Must match parameters given to encrypt
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

    // attempt to decrypt and check if decryption failed
    var plaintext = null;
    try {
      plaintext = sjcl.decrypt(aeskey, ct_json_str); //Do the decryption
    } catch(ex) {
      swal("Decryption Error", "Something went wrong...", "error");
      return;
    }
    if (plaintext == null) {
      swal("Decryption Error", "Something went wrong...", "error");
      return;
    }

    // truncate plaintext that gets displayed in the popup if too big (>150 
    // chars)
    if (plaintext.length > 150) {
      var popup_plaintext = plaintext.substring(0,150) + " ...";
    } else {
      var popup_plaintext = plaintext;
    }

    //Display as popup with options: close, copy to clipboard
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
        var invisibleTextArea = document.getElementById("invis");
        invisibleTextArea.style.display = "inline";
        invisibleTextArea.value = plaintext;
        invisibleTextArea.focus(); //Moves cursor to textarea
        invisibleTextArea.select(); //Selects (Highlights) text in textarea
        document.execCommand("copy");
        invisibleTextArea.style.display = "none";
      }
    });
    // update the timestamp to prevent replays
    // we do this at the very end of the encrypt method to ensure that we don't
    // prematurely update the timestamp if decryption fails at some point
    updateTimestamp(timestamp, sender_id);

  });
}


//Function encrypts highlighted text
/**
1. Take given RSA public key
2. Decrypt private key from local storage
3. Get the user's ID from local storage
4. Generate random string for AES key (8 words, 256 bits)
5. Get the selected text and encrypt it with AES
6. Encrypt with public key: (All will be 344 bytes each when encrypted)
  - user ID
  - timestamp
  - AES key
  - IV
7. Prepend these encrypted fields to the ciphertext to form
8. Hash the result of step 7, and sign using the private key
9. Prepend the signature to the result of step 7
10. Copy result to user's clipboard
**/ 
function encryptSelectedText(pubkey) {  
  if (pubkey == null || pubkey.length == 0) {
    swal("Error", "No public key found for the following ID: " + sender_id, "error");
    return;
  }
  // prompt the user for their password to decrypt their private key
  swal({
    title: "Password",
    text: "Please provide the password you used to encrypt your private key",
    type: "input",
    showCancelButton: true,
    closeOnConfirm: false,
  },
  function(inputValue){
    // do nothing if cancel
    if (inputValue === false) {
      return false;
    }
    // proceed with encryption otherwise
    encryptSubroutine(pubkey, inputValue);
  });
}

// encryption subroutine separated for readability
function encryptSubroutine(pubkey, pwd) {
  // get private key for signing
  var enc_prikey_str = localStorage.getItem(EE_PRIVATE);
  var enc_prikey = JSON.parse(enc_prikey_str);

  // attempt to decrypt and report if password is invalid
  var prikey = null;
  try {
    prikey = sjcl.decrypt(pwd, enc_prikey);
  } catch(ex) {
    invalidPassword();
    return;
  }
  if (prikey == null) {
    invalidPassword();
    return;
  }
  
  //get the sender's ID (user's ID)
  var sender_id = localStorage.getItem(EE_USER_ID);
  
  // sanity check that an ID was supplied when the private key was
  if (sender_id == null || sender_id.length == 0) {
    swal("Error","Cannot locate your ID. Please go to Manage and re-enter your ID, private key and password","error");
    return;
  }

  // generate a random 256 bit AES key to encrypt our message
  var aeskey = sjcl.random.randomWords(8); //8 * 32 == 256 bits
  var aes_key_str = sjcl.codec.base64.fromBits(aeskey);

  // get the selected text
  getSelectedText(function(selectedText) {
    var buf = selectedText.toString();
    if (buf == null || buf.length == 0) {
      swal("Error", "No text selected!", "error");
      return;
    }

    // set the ecnryption scheme for a 256-bit key
    var params = {};
    params["ks"] = 256; //AES-256 key

    // perform the encryption; AES-256 CCM mode
    // NOTE: although CCM mode is designed to provide integrity, we do no rely 
    // on it for that; essentially, we are just using CCM to provide CTR-mode
    // level confidentiality (we handle integrity/authenticity later on)
    var result_str = sjcl.encrypt(aeskey, buf, params); //do encryption
    var result_obj = sjcl.json.decode(result_str); //get JSON from returned string
    var ciphertext = sjcl.codec.base64.fromBits(result_obj.ct); 
    var iv = sjcl.codec.base64.fromBits(result_obj.iv);
    
    // get current time (this will prevent replay attacks)
    var timestamp = Date.now();
    var timestamp_str = timestamp.toString();
    
    // Encrypt timestamp, sender ID (e.g. email), AES key, and IV with RSA using 
    // public key of recipient
    var enc_timestamp_str = RSAEncrypt(timestamp_str, pubkey);
    var enc_sender_id = RSAEncrypt(sender_id, pubkey);
    var enc_key = RSAEncrypt(aes_key_str, pubkey); 
    var enc_iv = RSAEncrypt(iv, pubkey);

    //Construct the hybrid encrypted message
    var message = "";
    message += enc_sender_id;
    message += enc_timestamp_str;
    message += enc_key;
    message += enc_iv;
    message += ciphertext;
    
    // generate a hash of the hybrid encrypted message
    var message_digest = sjcl.hash.sha256.hash(message);
    var message_digest_str = sjcl.codec.hex.fromBits(message_digest);
    
    // encrypt the hash with sender's private key to generate a digital 
    // signature (this provides integrity and authenticity in our system)
    var digital_signature = RSASign(message_digest_str, prikey);
        
    // prepend the signature to the message to sign it
    var signed_message = digital_signature + message;

    //set the invisible element's value to the encrypted message
    var invisibleTextArea = document.getElementById("invis");
    invisibleTextArea.style.display = "inline";
    invisibleTextArea.value = signed_message;
    invisibleTextArea.focus(); //Moves cursor to textarea
    invisibleTextArea.select(); //Selects (Highlights) text in textarea

    //Copy selected encrypted text from invisible textarea to the clipboard
    document.execCommand("copy");
    invisibleTextArea.style.display = "none";

    swal({
      title: "Successful Encryption",
      text: "Ciphertext copied to clipboard",
      timer: 2000,
      showConfirmButton: true
    })
  });
}

// Displays alert for invalid password when decrypting private key
function invalidPassword() {
  swal("Error","The password you entered is invalid","error");
}

// Puts the public keys into the select list when user selects "Encrypt"
function showPublicKeys() {
  var selectDiv = document.getElementById("invis-select");
  var select = document.getElementById("public-key-select");
  var buttons = document.getElementById("buttons");

  //get the keylist from localStorage
  var keyList = JSON.parse(localStorage.getItem(EE_KEYLIST));
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
  var keyList = JSON.parse(localStorage.getItem(EE_KEYLIST));
  var key = keyList[keyname]; 

  // call the actual encryption routine
  encryptSelectedText(key);
  closeKeySelect(); //resets the display
}

// Hides the public key select form
// Returns the main menu to visible
function closeKeySelect() {
  document.getElementById("invis-select").style.visibility = "hidden";
  document.getElementById("buttons").style.visibility = "visible";
}

// registers onclick events
document.addEventListener('DOMContentLoaded', function() {
  document.getElementById("import").onclick = openKeyManagerTab;
  document.getElementById("decrypt").onclick = decryptSelectedText;

  document.getElementById("encrypt").onclick = showPublicKeys;
  document.getElementById("pubkey-button-select").onclick = selectPublicKey;
  document.getElementById("pubkey-button-cancel").onclick = closeKeySelect;
  
});