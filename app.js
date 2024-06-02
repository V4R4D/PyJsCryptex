var encrypted;

var apiUrl = "https://x0psw0czq3.execute-api.ap-south-1.amazonaws.com/prod";

// Send the #to_encrypt string to be encrypted by Python and populate the Encryption Result Section
$("#do_encrypt").click(function () {
  var post_data = {
    to_encrypt: $("#to_encrypt").val(),
  };

  $.ajax({
    url: apiUrl + "/encrypt",
    type: "POST",
    data: JSON.stringify(post_data),
    contentType: "application/json",
    success: function (data) {
      encrypted = data;
      $("#encrypt_key").val(data.key);
      $("#encrypt_iv").val(data.iv);
      $("#encrypt_ct").val(data.ciphertext);

      $("#do_decrypt").removeAttr("disabled");
    },
  });
});

// Output the decryption result to #decrypted, based on encrypted data from #do_encrypt
$("#do_decrypt").click(function () {
  var key = CryptoJS.enc.Hex.parse(encrypted.key),
    iv = CryptoJS.enc.Hex.parse(encrypted.iv),
    cipher = CryptoJS.lib.CipherParams.create({
      ciphertext: CryptoJS.enc.Base64.parse(encrypted.ciphertext),
    }),
    result = CryptoJS.AES.decrypt(cipher, key, {
      iv: iv,
      mode: CryptoJS.mode.CFB,
    });

  $("#decrypted").val(result.toString(CryptoJS.enc.Utf8));
});
