var siemModule = angular.module('SIEMModule', ['ui.bootstrap','chart.js']);

siemModule.config(function ($httpProvider) {
    $httpProvider.defaults.xsrfCookieName = "CSRF-TOKEN";
});


siemModule.controller('SIEMCtrl', function(siemService, $q, $uibModal) {
	var me = this,
	promises;
	
	me.AlertsByAppName = [];
	me.AlertsByIdentity = [];

	//used for the histogram chart
	//the timeInterval is in days if isDays is true, else it's in weeks
	me.timeIntervalOptions = [
		{
			display: "One week",
			timeInterval: 7,
			isDays: true
		},
		{
            display: "Two weeks",
            timeInterval: 14,
            isDays: true
        },
        {
            display: "One month",
            timeInterval: 4,
            isDays: false
        },
        {
            display: "Three months",
            timeInterval: 12,
            isDays: false
        },
        {
            display: "Six months",
            timeInterval: 24,
            isDays: false
        }
	]
    me.selectedTimeInterval = "One week";

	me.alertTypes = ["All", "Identity", "Application"];
	me.selectedAlertType = "All";

	me.topTenSelected = "identity";

	me.identityAlerts = {
	    labels: [],
        data: []
	};

	me.applicationAlerts = {
	    labels: [],
        data: []
    };

	me.doughnutChart = {
        labels: [],
        data: []
    };

	me.histogram = {
		labels: [],
		series: ['Alert Count'],
	    data: []
	};

	me.overviewData = [];

	/*********** run on page load ***********/
	getHistogramData(me.timeIntervalOptions[0]);

	getDoughnutChartData('All');

    getTopTenByApplication();
    
    getTopTenByIdentity();

    getOverviewData();

    /*********** called from page.xhtml ***********/
    me.updateHistogram = function() {
        getHistogramData(me.selectedTimeInterval);
	}

	me.updateDoughnutChart = function() {
        getDoughnutChartData(me.selectedAlertType);
    }

    me.updateTopTen = function() {
        if(me.topTenSelected.toLowerCase() === 'identity') {
            getTopTenByIdentity();
        } else {
            getTopTenByApplication();
        }
    }

    //links to alert page
    me.goToAlertPage = function(){
        window.location = SailPoint.CONTEXT_PATH + '/define/alerts/alerts.jsf?forceLoad=true#/alerts?linked-from-siem-widget=true';
    }

    /*********** utility functions ***********/
    function getHistogramData(timeinterval) {
        siemService.getByDates(timeinterval)
        .then(function (results) {
            processHistogramData(results);
        });
    }

    function getDoughnutChartData(alertType) {
        siemService.getByAlertTypes()
        .then(function (alerts) {
            processDoughnutData(alertType, alerts);
        });
    }

    function getTopTenByApplication() {
        siemService.getByAppName()
        .then(function(alerts) {
            me.AlertsByAppName = alerts.slice(0, 10);
        });
    }

    function getTopTenByIdentity() {
        siemService.getByIdentity()
        .then(function(alerts) {
            me.AlertsByIdentity = alerts;
        });
    }

    function getOverviewData() {

        //this is a bit ugly, implemented this way to ensure the fields appear in the right order
        siemService.getAlertCount('overview')
        .then(function(data) {
            me.overviewData = me.overviewData.concat(data);

            siemService.getAlertCount('account_metrics')
            .then(function(data) {
                me.overviewData = me.overviewData.concat(data);

                siemService.getAlertCount('application_metrics')
                .then(function(data) {
                    me.overviewData = me.overviewData.concat(data);
                });
            });
        });
    }

    function processHistogramData(data) {
        var histogramLabels = [];
        var histogramData = [];
        data.forEach(function(date) {
            histogramLabels.push(date.appName);
            histogramData.push(date.count);
        });

        me.histogram.labels = histogramLabels;
        me.histogram.data = histogramData;
    }

    function processDoughnutData(alertType, alertArray) {
        var doughnutChartLabels = [];
        var doughnutChartData = [];

        alertArray.forEach(function(alert) {
            if(alertType != "All") {
                if(alert.displayName.toLowerCase().includes(alertType.toLowerCase())) {
                    doughnutChartLabels.push(alert.displayName);
                    doughnutChartData.push(alert.count);
                }
            } else {
                doughnutChartLabels.push(alert.displayName);
                doughnutChartData.push(alert.count);
            }
        });

        me.doughnutChart.labels = doughnutChartLabels;
        me.doughnutChart.data = doughnutChartData;
    }
});

/**
 * Service that handles functionality.
 */

siemModule.service('siemService', function($http) {

    return {
    	getByAppName: function() {
    		var APP_URL = PluginHelper.getPluginRestUrl('SIEMPlugin/widget-service/alerts/count/application_count');
            return $http.get(APP_URL).then(function(response) {
                return JSON.parse(response.data);
            });
        },
	    getByIdentity: function() {
			var APP_URL = PluginHelper.getPluginRestUrl('SIEMPlugin/dashboardService/IdentityCountService');
	        return $http.get(APP_URL).then(function(response) {
	            return response.data.objects;
	        });
	    },
	    getByDates: function(timeIntervalOption) {
			var APP_URL = PluginHelper.getPluginRestUrl('SIEMPlugin/dashboardService/AlertDatesService/' +
				timeIntervalOption.timeInterval + '/' + timeIntervalOption.isDays);
	        return $http.get(APP_URL).then(function(response) {
	            return response.data.objects;
	        });
	    },
	    getByAlertTypes: function() {
			var APP_URL = PluginHelper.getPluginRestUrl('SIEMPlugin/widget-service/alerts/count/type_totals');
	        return $http.get(APP_URL).then(function(response) {
	            return JSON.parse(response.data);
	        });
	    },
        getAlertCount: function (countType) {
            var APP_URL = PluginHelper.getPluginRestUrl('SIEMPlugin/widget-service/alerts/count/' + countType);
            return $http.get(APP_URL).then(function (response) {
                return JSON.parse(response.data);
            });
        }
    };
});

/* commented for testing 
app.controller('BarCtrl', function($scope, $http) {

	$http.get("http://127.0.0.1:8080/RestProject/Rest/dashboardService/AppCountService").then(function(response) {

		$scope.labels = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday'];
		$scope.series = ['Alert Count'];
		$scope.data = [response.data.ByAlertNumbers];
	});

});

app.controller('DoughnutCtrl', function($scope, $http) {

	$http.get("http://127.0.0.1:8080/RestProject/Rest/dashboardService/AppCountService").then(function(response) {

		$scope.SIEMbyAppName = response.data.ByAppName;
		$scope.SIEMbyIdentity = response.data.ByIdentity;
		$scope.labels = [response.data.ByAlertType];
		$scope.data = [response.data.ByAlertNumbers];
	});

});
*/

