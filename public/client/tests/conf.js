'use strict';

let SpecReporter = require('jasmine-spec-reporter').SpecReporter;
require('protractor-console');

exports.config = {
  framework: 'jasmine',
  seleniumAddress: 'http://localhost:4444/wd/hub',
  suites: {
    login: 'e2e/login/**/*.spec.js',
    users: 'e2e/users/**/*.spec.js'
  },
  jasmineNodeOpts: {
    showColors: true, // Use colors in the command line report.
    includeStackTrace: false,
    isVerbose : true,
    print: function() {}
  },
  onPrepare: function () {
    jasmine.getEnv().addReporter(new SpecReporter({
      spec: {
        displayStacktrace: true
      }
    }));
  },
  plugins: [{
    package: 'protractor-console',
    logLevels: []
  }]
}
