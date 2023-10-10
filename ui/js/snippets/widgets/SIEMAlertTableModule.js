(function() {
    'use strict';

    var siemAlertTableWidgetFunction = function() {
        angular.module('sailpoint.home.desktop.app')
        .controller('SIEMAlertTableWidgetCtrl',['$uibModal', 'SIEMAlertTableWidgetService',
        function($uibModal, SIEMAlertTableWidgetService) {
            var me = this;

            me.alerts = [];

            me.pagedAlerts = [];
            me.currentPage = 1;
            me.itemsPerPage = 5;

            //populates dropdown
            me.alertTypes = [
                'identity/account', 'identity/accounts', 'identity/entitlement', 'identity/entitlements',
                'identity/entitlements-all', 'identity/password', 'identity/passwords', 'identity/certify',
                'identity/certify-all', 'application/groups', 'application/accounts', 'application/certify-group',
                'application/certify-all'
            ];
            me.activeAlertType = 'Please Select an Alert Type';

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

            //gets the selected alert type
            me.fetchAlertType = function(alertType) {
                me.activeAlertType = alertType;
                SIEMAlertTableWidgetService.getAlertType(alertType.replace('/', '-'))
                .then(function(alerts) {
                    me.alerts = alerts;
                    me.setPagingData();
                })
            }

            //links to alert page
            me.goToSiemPage = function(){
                window.location = SailPoint.CONTEXT_PATH + '/define/alerts/alerts.jsf?forceLoad=true#/alerts?linked-from-siem-widget=true';
            }

            //opens modal with alert details
            me.viewDetails = function(alert) {
                $uibModal.open({
                    animation : false,
                    templateUrl : PluginHelper.getPluginFileUrl('SIEMPlugin', 'ui/html/modals/alert-details.html'),
                    controller : 'SIEMAlertDetailsCtrl as ctrl',
                    backdrop: 'static',
                    resolve : {
                        alert : function() { return alert; }
                    }
                });
            }
        }])

        //modal controller
        .controller('SIEMAlertDetailsCtrl', ['$uibModalInstance', 'alert', function($uibModalInstance, alert){
            var alertView = this;
            alertView.alert = JSON.parse(JSON.stringify(alert));

            //converts created an processedDate from unix timestamp
            alertView.alert.created = new Date(alertView.alert.created).toLocaleString();

            if(alert.processedDate > 0) {
                alertView.alert.processedDate = new Date(alert.processedDate).toLocaleString();
            } else {
                alertView.alert.processedDate = 'N/A';
            }

            alertView.close = function() {

                $uibModalInstance.close();
            };
        }])
        .service('SIEMAlertTableWidgetService', ['$http', function($http) {
            return {
                getAlertType: function(alertType) {
                    var APP_URL = PluginHelper.getPluginRestUrl('SIEMPlugin/widget-service/alerts/' + alertType);
                    return $http.get(APP_URL)
                        .then(function(response) {
                            return JSON.parse(response.data);
                        });
                },
            }
        }])
        .directive('spSiemAlertTableWidget', function() {
            return {
                restrict: 'E',
                scope: {
                    widget: '=spWidget'
                },
                controller: 'SIEMAlertTableWidgetCtrl',
                controllerAs: 'widgetCtrl',
                bindToController: true,
                templateUrl: PluginHelper.getPluginFileUrl('SIEMPlugin', 'ui/html/widget/SIEMAlertTable.html')
            };
        });
    };

    PluginHelper.addWidgetFunction(siemAlertTableWidgetFunction);
})();