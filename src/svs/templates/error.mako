<%!
    import json

    def to_json(d):
        return json.dumps(d, indent=0)
%>

<!DOCTYPE html>

<html>
<head>
    <title>InAcademia Error</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="content-type" content="text/html;" charset="utf-8"/>

    <!-- Latest compiled and minified CSS -->
    <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.1/css/bootstrap.min.css">
    <link rel="stylesheet" href="/webroot/style.css">
</head>
<body>

<div class="row">
    <div class="wrapper col-md-8 col-md-offset-2">
        <div class="title row">
            <div class="col-md-11">
                <h1>${_("Error - An error occurred.")}</h1>
            </div>
            <!-- Language selection -->
            <div class="col-md-1">
                <form action="${form_action}" method="POST" >
                    <select name="lang" onchange="this.form.submit()" class="dropdown-menu-right">
                        <option value="en">EN</option>
                        <option value="sv">SV</option>
                        <option value="nl">NL</option>
                    </select>
                    <input type="hidden" name="error" value="${to_json(error) | u}">
                </form>
            </div>
        </div>

        <div class="row">
            <div class="col-md-12">
                <p>
                    ${_(error["message"])}
                </p>
            </div>
        </div>
        <hr>

        <table class="table table-striped">
            <tbody>
            <tr>
                <td class="col-md-2"><strong>${_("Timestamp")}:</strong></td>
                <td class="col-md-10">${error["timestamp"]}</td>
            </tr>

            <tr>
                <td class="col-md-2"><strong>${_("Error id")}:</strong></td>
                <td class="col-md-10">${error["uid"]}</td>
            </tr>
            </tbody>
        </table>

        <hr>

        <footer>
            <a href="https://www.inacademia.org">InAcademia</a> |
            <a href="https://www.inacademia.org/eula/">${_("Terms of service")}</a>
        </footer>
    </div>
</div>


<script type="application/javascript">
    "use strict";

    var lang = "${language}"
    var lang_option = document.querySelector("option[value=" + lang + "]");
    console.log(lang_option)
    lang_option.selected = true;
</script>

</body>
</html>