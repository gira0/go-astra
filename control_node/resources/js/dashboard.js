// resources/static/js/dashboard.js
function openTab(evt, tabName) {
    var i, tabcontent, tablinks;
    tabcontent = document.getElementsByClassName("tabcontent");
    for (i = 0; i < tabcontent.length; i++) {
        tabcontent[i].style.display = "none";
    }
    tablinks = document.getElementsByClassName("tablinks");
    for (i = 0; i < tablinks.length; i++) {
        tablinks[i].className = tablinks[i].className.replace(" active", "");
    }
    document.getElementById(tabName).style.display = "block";
    evt.currentTarget.className += " active";
}

function addNode() {
    // Add node logic here
}

function openAddNodeModal() {
    document.getElementById("addNodeModal").style.display = "block";
}

function closeAddNodeModal() {
    document.getElementById("addNodeModal").style.display = "none";
    document.getElementById("authKeyResult").innerHTML = "";
    // Restore the input, label and generate button for next use
    document.getElementById("authDuration").style.display = "inline-block";
    let lbl = document.querySelector("label[for='authDuration']");
    if (lbl) { lbl.style.display = "inline-block"; }
    document.getElementById("generateAuthKeyBtn").style.display = "inline-block";
}

document.querySelector(".add-node-button").addEventListener("click", openAddNodeModal);

document.getElementById("generateAuthKeyBtn").addEventListener("click", function() {
    let duration = document.getElementById("authDuration").value;
    if (duration < 1 || duration > 24) {
        alert("Please enter a duration between 1 and 24 hours.");
        return;
    }
    let formData = new FormData();
    formData.append("duration", duration);

    fetch("/generate_auth_key", {
        method: "POST",
        body: formData
    })
    .then(resp => resp.json())
    .then(data => {
        // Hide duration input, its label and the generate button
        document.getElementById("authDuration").style.display = "none";
        let lbl = document.querySelector("label[for='authDuration']");
        if (lbl) { lbl.style.display = "none"; }
        document.getElementById("generateAuthKeyBtn").style.display = "none";
        // Show the generated auth key and valid info
        document.getElementById("authKeyResult").innerHTML = 
          "Your Auth Key: " + data.authKey + "<br>Valid for " + data.validHours + " hours.";
    })
    .catch(err => {
        document.getElementById("authKeyResult").innerHTML = "Error: " + err;
    });
});