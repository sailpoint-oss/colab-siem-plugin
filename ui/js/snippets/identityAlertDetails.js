(function () {
    'use strict';

    var app =
        angular.module('IdentityAlertInjector', ['ui.bootstrap'])
        .config(function ($httpProvider) {
            $httpProvider.defaults.xsrfCookieName = "CSRF-TOKEN";
        })
        .controller('IdentityAlertInjectorCtrl', ['IdentityAlertInjectorService', function (IdentityAlertInjectorService) {
            var me = this;

            //parses the identity id from the url
            var currentUrl = window.location.href;
            me.id = currentUrl.match(/(id=.*?&)|(id=.*)/g)[0].slice(3).replace('&', '');

            me.alerts = [];
            me.pagedAlerts = [];
            me.currentPage = 1;
            me.itemsPerPage = 5;

            me.reverse = false;
            me.orderedProperty = null;

            //get alerts using the id
            IdentityAlertInjectorService.getIdentityAlert(me.id)
            .then(function (alerts) {
                //converts created and processedDate from unix timestamp to date
                alerts.forEach(function (alert) {
                    alert.created = new Date(alert.created);
                });

                me.alerts = alerts;
                me.setPagingData();
            });

            //determines number of pages needed for the table
            me.numPages = function () {
                return Math.ceil(me.alerts.length / me.numPerPage);
            };

            //creates pages for pagination
            me.setPagingData = function() {
                var pagedData = me.alerts.slice(
                    (me.currentPage - 1) * me.itemsPerPage,
                    me.currentPage * me.itemsPerPage
                );
                me.pagedAlerts = pagedData;
            }

            //sorts the array based on selected property
            //sorts all alerts then paginates them
            me.sort = function (property) {
                me.orderedProperty = property;

                function compare(a,b) {
                    if (typeof a[property] === "string")
                        return a[property].localeCompare(b[property]);
                    else if (typeof a[property] === "date") {
                        if (a[property].getTime() < b[property].getTime())
                            return -1;
                        if (a[property].getTime() > b[property].getTime())
                            return 1;
                        return 0;
                    } else {
                        if (a[property] < b[property])
                            return -1;
                        if (a[property] > b[property])
                            return 1;
                        return 0;
                    }
                }

                function compareReverse(a,b) {
                    if (typeof a[property] === "string")
                        return b[property].localeCompare(a[property]);
                    else if (typeof a[property] === "date") {
                        if (a[property].getTime() > b[property].getTime())
                            return -1;
                        if (a[property].getTime() < b[property].getTime())
                            return 1;
                        return 0;
                    } else {
                        if (a[property] > b[property])
                            return -1;
                        if (a[property] < b[property])
                            return 1;
                        return 0;
                    }
                }

                if(me.reverse) {
                    me.alerts.sort(compareReverse);
                } else {
                    me.alerts.sort(compare);
                }

                me.reverse = !me.reverse;
                me.setPagingData();
            }
        }])
        .service('IdentityAlertInjectorService', ['$http', function($http) {
            return {
                getIdentityAlert: function(identityId) {
                    var APP_URL = PluginHelper.getPluginRestUrl('SIEMPlugin/widget-service/alerts/identity/' + identityId);
                    return $http.get(APP_URL)
                    .then(function(response) {
                        return JSON.parse(response.data);
                    });
                },
            }
        }]);

    //this guys pretty beastly, mostly because of the element string
    //polls for the 'selector' element, inserts the angular snippet once it exists
    function addAngularSnippet(selector, intervalTime) {
        var interval = setInterval(function () {
            if (jQuery(selector).length > 0) {
                var element =
                    '<div ng-if="ctrl.alerts.length != 0">' +
                        '<span class="spContentTitle">Identity SIEM Alert History</span>' +
                        '<div style="width: 97%; margin:10px;padding:10px 0">' +
                            '<div class="panel">' +
                                '<div class="panel-body data no-padder">' +
                                    '<table class="table table-responsive m-b-none">' +
                                        '<thead class="bg-light">' +
                                            '<tr>' +
                                                '<th ng-click="ctrl.sort(\'alertType\')" class="clickable">' +
                                                    'Alert Type' +
                                                    '<span style="margin-left: 5px;">' +
                                                        '<i ng-class="(ctrl.reverse) ? ' +
                                                            '\'fa fa-chevron-up\' : \'fa fa-chevron-down\'" ' +
                                                            'ng-if="ctrl.orderedProperty == \'alertType\'"></i>' +
                                                    '</span>' +
                                                '</th>' +
                                                '<th ng-click="ctrl.sort(\'level\')" class="clickable">' +
                                                    'Alert Level' +
                                                    '<span style="margin-left: 5px;">' +
                                                        '<i ng-class="(ctrl.reverse) ' +
                                                        '? \'fa fa-chevron-up\' : \'fa fa-chevron-down\'" ' +
                                                        'ng-if="ctrl.orderedProperty == \'level\'"></i>' +
                                                    '</span>' +
                                                '</th>' +
                                                '<th ng-click="ctrl.sort(\'sourceApplication\')" class="clickable">' +
                                                    'Application' +
                                                    '<span style="margin-left: 5px;">' +
                                                        '<i ng-class="(ctrl.reverse) ' +
                                                        '? \'fa fa-chevron-up\' : \'fa fa-chevron-down\'" ' +
                                                        'ng-if="ctrl.orderedProperty == \'sourceApplication\'"></i>' +
                                                    '</span>' +
                                                '</th>' +
                                                '<th ng-click="ctrl.sort(\'created\')" class="clickable">' +
                                                    'Created On' +
                                                    '<span style="margin-left: 5px;">' +
                                                        '<i ng-class="(ctrl.reverse) ' +
                                                        '? \'fa fa-chevron-up\' : \'fa fa-chevron-down\'" ' +
                                                        'ng-if="ctrl.orderedProperty == \'created\'"></i>' +
                                                    '</span>' +
                                                '</th>' +
                                                '<th ng-click="ctrl.sort(\'action\')" class="clickable">' +
                                                    'Action' +
                                                    '<span style="margin-left: 5px;">' +
                                                        '<i ng-class="(ctrl.reverse) ' +
                                                        '? \'fa fa-chevron-up\' : \'fa fa-chevron-down\'" ' +
                                                        'ng-if="ctrl.orderedProperty == \'action\'"></i>' +
                                                    '</span>' +
                                                '</th>' +
                                            '</tr>' +
                                        '</thead>' +
                                        '<tbody>' +
                                            '<tr ng-repeat="alert in ctrl.pagedAlerts">' +

                                                //check if each property is null, use emdash if it is
                                                '<td ng-if="alert.alert_type">{{ alert.alert_type }}</td>' +
                                                '<td ng-if="!alert.alert_type">&#8212;</td>' +

                                                '<td ng-if="alert.level">{{ alert.level }}</td>' +
                                                '<td ng-if="!alert.level">&#8212;</td>' +

                                                '<td ng-if="alert.source_application">{{ alert.source_application }}</td>' +
                                                '<td ng-if="!alert.source_application">&#8212;</td>' +

                                                '<td ng-if="alert.created">{{ alert.created.toLocaleString() }}</td>' +
                                                '<td ng-if="!alert.created">&#8212;</td>' +

                                                '<td ng-if="alert.action">{{ alert.action }}</td>' +
                                                '<td ng-if="!alert.action">&#8212;</td>' +
                                            '</tr>' +
                                        '</tbody>' +
                                    '</table>' +
                                '</div>' +

                                //pagination
                                '<div class="panel-footer" ng-if="ctrl.alerts.length > 5">' +
                                    '<div class="row">' +
                                        '<div class="col-xs-5 col-sm-4">' +
                                        '</div>' +
                                        '<div class="col-xs-4 col-sm-3 text-center">' +
                                            '<p ng-if="ctrl.alerts.length > 5">' +
                                            '{{1 + 5 * (ctrl.currentPage - 1) }}&#8211;{{5 * ctrl.currentPage > ctrl.alerts.length ?' +
                                            'ctrl.alerts.length : 5 * ctrl.currentPage }} of {{ ctrl.alerts.length }}' +
                                            '</p>' +
                                        '</div>' +
                                        '<div class="col-xs-2 col-sm-5 text-right hidden-xs">' +
                                            '<ul uib-pagination class="pagination pagination-sm" style="margin: 0;" ' +
                                            'max-size="3" ' +
                                            'total-items="ctrl.alerts.length" ng-model="ctrl.currentPage"' +
                                            'boundary-links="true" first-text="&laquo;" last-text="&raquo;"' +
                                            'previous-text="&lsaquo;" next-text="&rsaquo;"' +
                                            'ng-change="ctrl.setPagingData()" items-per-page="ctrl.itemsPerPage"></ul>' +
                                        '</div>' +
                                    '</div>' +
                    '           </div>' +
                            '</div>' +
                        '</div>' +
                    '</div>';

                PluginHelper.addSnippetController("IdentityAlertInjector", element, selector);

                //resize panel to fit our table
                //needs to be in timeout so everything loads before it gets heights
                setTimeout(function () {
                    var height = jQuery('#angularSnippetContainer').outerHeight(true);
                    var panelHeight = parseInt(jQuery('#identityTabPanel-body').css("height"));
                    var newHeight = panelHeight + height;
                    jQuery('#identityTabPanel').css('height', newHeight);
                    jQuery('#identityTabPanel-body').css('height', newHeight);
                    jQuery('div.x-panel.x-tabpanel-child.x-panel-default').css('height', newHeight);
                }, 50);

                clearInterval(interval);
            }
        }, intervalTime);
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

    //function to add a custom element to nest our table within
    //needed because addAngularSnippet does not allow you to add snippet after an element
    var addCustomElement = function() {
        jQuery('#certHistoryContentContainer').after('<div class="spAjaxContent" id="angularSnippetContainer"></div>');
    }

    //adds our table when the history tab is clicked
    var onTabClick = function() {
        jQuery(".x-tab:contains('History')").click(function () {
            setTimeout(function () {
                if(!(jQuery('#angularSnippetContainer').length > 0)){
                    applyWhenElementExists('#identityHistoryWrapperPanel', addCustomElement, 50);
                    addAngularSnippet('#angularSnippetContainer', 50);
                }
            }, 200)
        })
    }

    //waits for x-tab to exist, then applies our function to it
    applyWhenElementExists(".x-tab", onTabClick, 50);
})
();

