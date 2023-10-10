jQuery(document).ready(function() {
    'use strict';

    var currentUrl = window.location.href;
    if(currentUrl.includes('linked-from-siem-widget=true')) {
        applyWhenElementExists("div.col-sm-6.col-md-3:contains(\'Source\')", selectSIEM, 50);
    }

    function selectSIEM() {
        jQuery("div.col-sm-6.col-md-3:contains('Type') button").click();

        applyWhenElementExists("li:contains('SIEM Alert')", function() {
            jQuery("li:contains('SIEM Alert')").click();
            applyWhenElementExists("sp-column-data", function() {
                jQuery("button:contains('Apply')").click();
            }, 50)
        }, 50);
    }

    //utility function that polls for element and adds our element once it exists
    function applyWhenElementExists(selector, myFunction, intervalTime) {
        var interval = setInterval(function () {
            if (jQuery(selector).length > 0) {
                myFunction();
                clearInterval(interval);
            }
        }, intervalTime);
    }
});