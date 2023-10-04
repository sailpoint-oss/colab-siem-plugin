var SIEMURL = SailPoint.CONTEXT_PATH + '/plugins/pluginPage.jsf?pn=SIEMPlugin';
jQuery(document).ready(function(){
    jQuery("ul.navbar-right li:first")
        .before(
            '<li class="dropdown">' +
            '		<a href="' + SIEMURL + '" tabindex="0" role="menuitem" title="View your Dashboard">' +
            '			<i role="presenation" class="fa fa fa-pie-chart fa-lg"></i>' +
            '		</a>' +
            '</li>'
        );
});