<%!
    import json
    def to_json(d):
        return json.dumps(d, indent=0)
%>

<!DOCTYPE html>

<html>
<head>
    <title><%block name="head_title"></%block></title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="content-type" content="text/html;" charset="utf-8"/>

    <!-- Latest compiled and minified CSS -->
    <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap.min.css">
    <link rel="stylesheet" href="/static/font-awesome.min.css">
    <link rel="stylesheet" href="/static/style.css">

    <script src="https://ajax.googleapis.com/ajax/libs/jquery/1.11.3/jquery.min.js"></script>
</head>
<body>

<div class="container">
  <div class="header text-muted">
    <div class="row">
      <div class="col-md-10 sp-icon-container logo">
        <img src="/static/InAcademia.png">
      </div>
      <!-- Language selection -->
      <div class="col-md-2 align-right sp-col-2">
        <form action="${form_action}" method="GET">
          <select name="lang" id="lang" onchange="this.form.submit()">
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
          <%block name="extra_inputs"></%block>
        </form>
      </div>
    </div>
    <div class="row col-md-12 sp-title-container">
      <h3 class="sp"><%block name="page_header"></%block></h3>
    </div>
    <div class="row clearfix"></div>
  </div>
  <div class="row">&nbsp;</div>
  <div class="clearfix">&nbsp;</div>

  <div class="content">${self.body()}</div>
  <footer><%block name="footer"></%block></footer>
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