'use strict';

require('../../app');
var angular = require('angular');

angular.module('deckApp')
  .controller('ServerGroupBasicSettingsCtrl', function($scope, modalWizardService, _) {

    $scope.state.loading = true;

    var populateRegions = function() {
      $scope.regions = $scope.regionsKeyedByAccount[$scope.command.credentials].regions;
    };
    populateRegions();

    var populateRegionalImages = function() {
      $scope.images = _($scope.packageImages)
        .filter({'region': $scope.command.region})
        .valueOf();
    };
    populateRegionalImages();

    var populateRegionalSubnetPurposes = function() {
      $scope.regionSubnetPurposes = _($scope.subnets)
        .filter({'account': $scope.command.credentials, 'region': $scope.command.region, 'target': 'ec2'})
        .pluck('purpose')
        .uniq()
        .map(function(purpose) { return { purpose: purpose, label: purpose };})
        .valueOf();
    };
    populateRegionalSubnetPurposes();

    this.accountUpdated = function() {
      populateRegions();
      onRegionChange();
    };

    this.regionUpdated = function () {
      onRegionChange();
      populateRegionalImages();
    };

    this.subnetUpdated = function() {
      var subnet = _($scope.subnets)
        .find({'purpose': $scope.command.subnetType, 'account': $scope.command.credentials, 'region': $scope.command.region});
      $scope.command.vpcId = subnet ? subnet.vpcId : null;
    };

    var onRegionChange = function() {
      populateRegionalSubnetPurposes();
    };

  });
