<%
    def print_released_attributes(released_attributes):
        result = ""
        for attribute, value in released_attributes.iteritems():
            attribute_title = _(attribute).capitalize()

            # more human-friendly and avoid "u'" prefix for unicode strings in list
            if isinstance(value, list):
                value = ", ".join(value)

            result += u"<strong>{title}</strong><br><pre>    {value}</pre>".format(title=attribute_title, value=value)

        return result

    import json
    def to_json(d):
        return json.dumps(d, indent=0)
%>

<!DOCTYPE html>

<html>
<head>
    <title>InAcademia Consent</title>
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
                <h1>${_("Consent - Your consent is required to continue.")}</h1>
            </div>
            <!-- Language selection -->
            <div class="col-md-1">
                <form action="${form_action}" method="POST">
                    <select name="lang" onchange="this.form.submit()" class="dropdown-menu-right">
                        <option value="en">EN</option>
                        <option value="sv">SV</option>
                        <option value="nl">NL</option>
                    </select>
                    <input type="hidden" name="state" value="${to_json(state) | u}">
                    <input type="hidden" name="released_attributes" value="${to_json(released_attributes) | u}">
                </form>
            </div>
        </div>

        ${consent_question}

        <br>
        <hr>


        <form name="give_consent" action="${form_action}/ok" method="GET" style="float: left">
            <input type="submit" value="${_('Ok, accept')}">
            <input type="hidden" name="state" value="${to_json(state) | u}">
            <input type="hidden" name="released_attributes" value="${to_json(released_attributes) | u}">
        </form>
        <form name="deny_consent" action="${form_action}/fail" method="GET" style="float: left; clear: right;">
            <input type="submit" value="${_('No, cancel')}">
            <input type="hidden" name="state" value="${to_json(state) | u}">
        </form>

        <br>
        <br>

        <div style="clear: both;">
            ${print_released_attributes(released_attributes)}
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

    var lang = "${language}"
    var lang_option = document.querySelector("option[value=" + lang + "]");
    console.log(lang_option)
    lang_option.selected = true;
</script>

</body>
</html>