var object = require('lodash/fp/object');
var data = require('../data.js');
var localStorage = require("../localStorage")

var LoginPage = function() {
  this.loginUrl = data.domain + 'app/login';

  this.email = element(by.model('loginCtrl.credentials.email'));
  this.password = element(by.model('loginCtrl.credentials.password'));
  this.button = element(by.id('btn-loginCtrl-login'));

  this.visit = function() {
    return browser.get(this.loginUrl);
  }

  this.login = function(credentials) {
    credentials = object.merge(data.validAdminUser, (credentials) ? credentials : {} );

    this.email.sendKeys(credentials.email);
    this.password.sendKeys(credentials.password);

    var loginPromisse = this.button.click()

    browser.sleep(1000); //wait set localstorage

    return loginPromisse;
  };

  this.logout = function() {
    browser.driver.get(data.domain);
    localStorage.clear();
  }
};
module.exports = LoginPage;
