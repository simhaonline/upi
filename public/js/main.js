// ===== main.js =====
$(document).ready(function () {
  let currentOrder = null; // will store { outTradeNo, upiUrl, qrBase64, amount }

  /************************************************************************
   * 1) On page load, call /api/create-order with a fixed amount (e.g. 500)
   ************************************************************************/
  function createOrder(amount = 500) {
    $.ajax({
      url: "/api/create-order",
      method: "POST",
      contentType: "application/json",
      data: JSON.stringify({ amount: amount }),
      success: function (resp) {
        // resp = { outTradeNo, upiUrl, qrBase64 }
        currentOrder = resp;
        $("#outTradeNo").text(resp.outTradeNo);
        $("#amountText").text(amount);

        if (resp.qrBase64) {
          // If API returned a base64‐PNG for the QR, simply display it:
          $("#qrCodeImg")
            .attr("src", "data:image/png;base64," + resp.qrBase64)
            .show();
          $("#qrCanvas").hide();
        } else if (resp.upiUrl) {
          // If API returned only the UPI URL, generate a QR with qrcode.js
          $("#qrCodeImg").hide();
          $("#qrCanvas").show();

          // Use QRCode.js to render into #qrCanvas
          new QRCode(document.getElementById("qrCanvas"), {
            text: resp.upiUrl,
            width: 250,
            height: 250,
            colorDark: "#000000",
            colorLight: "#ffffff",
            correctLevel: QRCode.CorrectLevel.H,
          });
        } else {
          alert("Error: no QR data received from API.");
        }
      },
      error: function (xhr) {
        console.error("Error creating order:", xhr.responseText);
        alert("Failed to create order. Check console for details.");
      },
    });
  }

  // Immediately create an order of ₹ 500 on page load.
  createOrder(500);

  /************************************************************************
   * 2) “Save QRCode” → Download the QR as a PNG
   ************************************************************************/
  $("#downloadQrBtn").click(function () {
    // If <img id="qrCodeImg"> is visible, download that
    if ($("#qrCodeImg").is(":visible")) {
      const img = document.getElementById("qrCodeImg");
      const a = document.createElement("a");
      a.href = img.src;
      a.download = currentOrder.outTradeNo + "_qrcode.png";
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      return;
    }

    // Otherwise, if <canvas id="qrCanvas"> is used, download that
    if ($("#qrCanvas").is(":visible")) {
      const canvas = document.getElementById("qrCanvas");
      canvas.toBlob(function (blob) {
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = currentOrder.outTradeNo + "_qrcode.png";
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
      });
    }
  });

  /************************************************************************
   * 3) “Submit Ref Number” → call /api/verify-utr 
   ************************************************************************/
  $("#submitUtrBtn").click(function () {
    const utr = $("#utrInput").val().trim();
    $("#utrFeedback").text(""); // clear previous

    if (!/^\d{12}$/.test(utr)) {
      $("#utrFeedback").text("Please enter a valid 12‐digit UTR.");
      return;
    }
    if (!currentOrder || !currentOrder.outTradeNo) {
      $("#utrFeedback").text("Order not yet created. Please wait.");
      return;
    }

    // Disable button to prevent double submits
    $("#submitUtrBtn").prop("disabled", true).text("Checking...");

    $.ajax({
      url: "/api/verify-utr",
      method: "POST",
      contentType: "application/json",
      data: JSON.stringify({
        outTradeNo: currentOrder.outTradeNo,
        utr: utr,
      }),
      success: function (resp) {
        // resp = { status: "SUCCESS" | "PENDING" | "FAILED" }
        if (resp.status === "SUCCESS") {
          alert("✅ Payment confirmed! Your UTR has been recorded.");
          $("#submitUtrBtn").text("Submit Ref Number").prop("disabled", false);
        } else if (resp.status === "PENDING") {
          $("#utrFeedback").text("Payment not yet confirmed. Please wait a few seconds and try again.");
          $("#submitUtrBtn").text("Submit Ref Number").prop("disabled", false);
        } else {
          $("#utrFeedback").text("Payment failed or was not recognized. Please retry or contact support.");
          $("#submitUtrBtn").text("Submit Ref Number").prop("disabled", false);
        }
      },
      error: function (xhr) {
        console.error("Error verifying UTR:", xhr.responseText);
        $("#utrFeedback").text("Server error. Please try again later.");
        $("#submitUtrBtn").text("Submit Ref Number").prop("disabled", false);
      },
    });
  });
});
