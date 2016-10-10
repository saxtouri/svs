<%!
    def list2str(claim):
        # more human-friendly and avoid "u'" prefix for unicode strings in list
        if isinstance(claim, list):
            claim = ", ".join(claim)
        return claim
%>

<!DOCTYPE html>

<html>
<head>
    <title>InAcademia Consent</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="content-type" content="text/html;" charset="utf-8"/>

    <!-- Latest compiled and minified CSS -->
    <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.1/css/bootstrap.min.css">
    <link rel="stylesheet" href="/consent.css">
</head>
<body>

<div class="row">
    <div class="wrapper col-md-8 col-md-offset-2">
        <div class="title row">
            <div class="col-md-11">
                <h1>${_("Consent - Your consent is required to continue.")}</h1>
            </div>
            <!-- Language selection -->
            <div class="col-md-1">
                <form action="${form_action}" method="POST">
                    <select name="lang" id="lang" onchange="this.form.submit()" class="dropdown-menu-right">
                        <option value="af">AF</option>
                        <option value="en">EN</option>
                        <option value="cs">CS</option>
                        <option value="da">DA</option>
                        <option value="de">DE</option>
                        <option value="el">EL</option>
                        <option value="es_419">ES</option>
                        <option value="et">ET</option>
                        <option value="fr">FR</option>
                        <option value="hu">HU</option>
                        <option value="lt">LT</option>
                        <option value="nl">NL</option>
                        <option value="pt">PT</option>
                        <option value="ru">RU</option>
                        <option value="sv">SV</option>
                    </select>
                </form>
            </div>
        </div>

        ${_('{client_name} requires the information below to be transferred:').format(client_name='<strong>' + client_name + '</strong>')}

        <br>
        <hr>

        <form name="allow_consent" action="${form_action}/allow" method="GET"
              style="float: left">
            <button id="submit_ok" type="submit">${_('Ok, accept')}</button>
        </form>
        <form name="deny_consent" action="${form_action}/deny" method="GET"
              style="float: left; clear: right;">
            <button id="submit_deny" type="submit">${_('No, cancel')}</button>
        </form>

        <br>
        <br>

        <div style="clear: both;">
            % for attribute in released_attributes:
                <strong>${_(attribute).capitalize()}</strong><br>
                <pre>    ${released_attributes[attribute] | n, list2str}</pre>
            % endfor
        </div>
        <br>

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