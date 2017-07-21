var object = require('lodash/fp/object');
var data = require('../data.js');
var helper = require('../helper.js');
var localStorage = require("../localStorage");

var UserPage = function() {
  this.userUrl = data.domain + 'app/usuario';
  this.name = element(by.model('usersCtrl.resource.name'));
  this.email = element(by.model('usersCtrl.resource.email'));
  this.nameOrEmail = element(by.model('usersCtrl.queryFilters.nameOrEmail'));

  this.resourcesList = element.all(by.repeater('user in usersCtrl.resources'));

  this.goToFormButton = element(by.id('btn-usersCtrl-goToForm'));
  this.saveButton = element(by.id('btn-usersCtrl-save'));
  this.filterButton = element(by.id('btn-usersCtrl-filter'));


  this.visit = function() {
    return browser.get(this.userUrl);
  }

  this.save = function(user) {
    user = object.merge(data.validUserData, (user) ? user : {} );

    this.goToFormButton.click();

    this.name.sendKeys(user.name);
    this.email.sendKeys(user.email);

    return this.saveButton.click();

  }

  this.update = function(user) {
    var userListItem = this.findUserByEmailInList(user.email);

    userListItem.click();

    this.name.clear();
    this.email.clear();

    this.name.sendKeys(user.name);
    this.email.sendKeys(user.email);

    return this.saveButton.click();
  }

  this.search = function(nameOrEmail) {
    this.nameOrEmail.clear();
    this.nameOrEmail.sendKeys(nameOrEmail);

    return this.filterButton.click();
  }

  this.findUserByEmailInList = function(email) {
      var userFound = this.resourcesList.filter(function(item) {
        return item.element(by.css('.user-list-info-email')).getText().then(function(userMail) {
          return (userMail.indexOf(email) > -1);
        });
      });

      return userFound.first();
  }

  this.remove = function(email) {
    var userFound = this.findUserByEmailInList(email);
    var btnRemove = userFound.element(by.css("[id*=btn-usersCtrl-remove-]"));

    btnRemove.click();
    browser.sleep(1000);

    return helper.getModalYesButton().click();
  }

};
module.exports = UserPage;
