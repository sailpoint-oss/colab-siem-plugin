(function() {
    'use strict';

    var siemAlertOverviewWidgetFunction = function() {
        angular.module('sailpoint.home.desktop.app')
        .controller('SIEMAlertOverviewWidgetCtrl', ['$scope', 'SIEMAlertOverviewWidgetService',
            function ($scope, SIEMAlertOverviewWidgetService) {
                var me = this;

                me.alerts = [];

                me.pagedAlerts = [];
                me.currentPage = 1;
                me.itemsPerPage = 6;

                SIEMAlertOverviewWidgetService.getAlertCount('overview')
                .then(function(alertCounts) {
                    me.alerts = alertCounts;
                    me.setPagingData();
                })

                me.loadOverview = function() {
                    SIEMAlertOverviewWidgetService.getAlertCount('overview')
                    .then(function(alertCounts) {
                        me.alerts = alertCounts;
                        me.setPagingData();
                    })
                };

                me.loadAlertTypeTotals = function() {
                    SIEMAlertOverviewWidgetService.getAlertCount('type_totals')
                    .then(function(alerts) {
                        me.alerts = alerts;
                        me.setPagingData();
                    });
                }

                me.loadAccountMetrics = function() {
                    SIEMAlertOverviewWidgetService.getAlertCount('account_metrics')
                    .then(function(alerts) {
                        me.alerts = alerts;
                        me.setPagingData();
                    });
                }

                me.loadApplicationMetrics = function() {
                    SIEMAlertOverviewWidgetService.getAlertCount('application_metrics')
                    .then(function(alerts) {
                        me.alerts = alerts;
                        me.setPagingData();
                    });
                }

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

                //links to alert page
                me.goToSiemPage = function(){
                    window.location = SailPoint.CONTEXT_PATH + '/define/alerts/alerts.jsf?forceLoad=true#/alerts?linked-from-siem-widget=true';
                }
            }])
        .service('SIEMAlertOverviewWidgetService', ['$http', function ($http) {
            return {
                getAlertCount: function (countType) {
                    var APP_URL = PluginHelper.getPluginRestUrl('SIEMPlugin/widget-service/alerts/count/' + countType);
                    return $http.get(APP_URL).then(function (response) {
                        return JSON.parse(response.data);
                    });
                }
            }
        }])
        .directive('spSiemAlertOverviewWidget', function () {
            return {
                restrict: 'E',
                scope: {
                    widget: '=spWidget'
                },
                controller: 'SIEMAlertOverviewWidgetCtrl',
                controllerAs: 'widgetCtrl',
                bindToController: true,
                templateUrl: PluginHelper.getPluginFileUrl('SIEMPlugin', 'ui/html/widget/SIEMAlertOverview.html')
            };
        });
    }

    PluginHelper.addWidgetFunction(siemAlertOverviewWidgetFunction);
})();

