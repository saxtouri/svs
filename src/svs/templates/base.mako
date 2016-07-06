<%!
    import json
    def to_json(d):
        return json.dumps(d, indent=0)
%>

<!DOCTYPE html>

<html>
<head>
    <title>InAcademia <%block name="head_title"></%block></title>
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
                <h1><%block name="page_header"></%block></h1>
            </div>
            <!-- Language selection -->
            <div class="col-md-1">
                <form action="${form_action}" method="POST">
                    <select name="lang" id="lang" onchange="this.form.submit()" class="dropdown-menu-right">
                        <option value="en">EN</option>
                        <option value="cs">CS</option>
                        <option value="da">DA</option>
                        <option value="de">DE</option>
                        <option value="el">EL</option>
                        <option value="es_419">ES</option>
                        <option value="fr">FR</option>
                        <option value="hu">HU</option>
                        <option value="lt">LT</option>
                        <option value="nl">NL</option>
                        <option value="pt">PT</option>
                        <option value="ru">RU</option>
                        <option value="sv">SV</option>
                    </select>
                    <%block name="extra_inputs"></%block>
                </form>
            </div>
        </div>

        ${self.body()}

        <hr>
        <footer>
            <a href="https://www.inacademia.org">InAcademia</a> |
            <a href="https://www.inacademia.org/eula/">${_("Terms of service")}</a>
        </footer>
    </div>
</div>


<script type="application/javascript">
    "use strict";

    // Mark the selected language in the dropdown
    var lang = "${language}";
    var lang_option = document.querySelector("option[value=" + lang + "]");
    lang_option.selected = true;
</script>

</body>
</html>