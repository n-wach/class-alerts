function info(url) {
    window.open(url, '');
}

function visit(url) {
    window.location = url;
}

function post(path, params, method) {
    method = method || "POST";
    var form = document.createElement("form");

    form.setAttribute("method", method);
    form.setAttribute("action", path);

    form.appendChild(document.getElementById("csrf_token"));

    for (var key in params) {
        if (params.hasOwnProperty(key)) {
            var hiddenField = document.createElement("input");
            hiddenField.setAttribute("type", "hidden");
            hiddenField.setAttribute("name", key);
            hiddenField.setAttribute("value", params[key]);

            form.appendChild(hiddenField);
        }
    }
    form.style.display = "none";
    document.body.appendChild(form);
    form.submit();
}

var requiredComponents = [];

//  push it to array and remove required attribute
window.addEventListener("load", function (e) {
    requiredComponents = document.querySelectorAll("[required]");
    requiredComponents.forEach(function (e) {
        e.removeAttribute('required');
        e.parentElement.classList.remove("is-invalid")
    });
    document.querySelectorAll("input[type=submit]").forEach(function (e) {
        e.addEventListener("click", function () {
            requiredComponents.forEach(function (e) {
                e.setAttribute('required', true)
            })
        })
    });
});
