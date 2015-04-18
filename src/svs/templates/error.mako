<%inherit file="base.mako"/>

<%block name="head_title">Error</%block>
<%block name="page_header">${_("Error - An error occurred.")}</%block>
<%block name="extra_inputs">
    <input type="hidden" name="error" value="${self.attr.to_json(error) | u}">
</%block>

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