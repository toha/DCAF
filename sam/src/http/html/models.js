//
// DCAF Authorization Subject (CAMs)
// Model and Collection
//
var DCAFSubject = Backbone.Model.extend({
  urlRoot : '/cfg/subjects',
  idAttribute: "cert_fingerprint",
  defaults : function() { return {}; },

  toggle : function() { this.save(); }

});

var DCAFSubjectList = Backbone.Collection.extend({

  initialize : function() {
    this.on('reset', this.testreset, this);
    this.on('add', this.testadd, this);
    this.on('remove', this.testremove, this);
    this.on('change', this.testchange, this);
  },

  // Reference to this collection's model.
  model : DCAFSubject,
  url : '/cfg/subjects',

  remaining : function() { return this.where({done : false}); },
  byFingerprint : function(fp) { return this.where({cert_fingerprint : fp}); },

  testreset : function() { console.log("testreset"); },
  testadd : function() { console.log("testadd"); },
  testremove : function() { console.log("testremove"); },
  testchange : function() { console.log("testchange"); }

});

//
// DCAF Authorization Object ((Resource) Servers)
// Model and Collection
//
var DCAFServer = Backbone.Model.extend({
  urlRoot : '/cfg/rs',
  defaults : function() { return {}; },

});

var DCAFServerList = Backbone.Collection.extend({

  initialize : function() {
    this.on('reset', this.testreset, this);
    this.on('add', this.testadd, this);
    this.on('remove', this.testremove, this);
    this.on('change', this.testchange, this);
  },

  // Reference to this collection's model.
  model : DCAFServer,
  url : '/cfg/rs',

  remaining : function() { return this.where({done : false}); },
  byId : function(fp) { return this.where({id : fp}); },
  testreset : function() { console.log("testreset"); },
  testadd : function() { console.log("testadd"); },
  testremove : function() { console.log("testremove"); },
  testchange : function() { console.log("testchange"); }

});

//
// DCAF SAM Access Rules
// Model and Collection
//
var DCAFRule = Backbone.Model.extend({
  urlRoot : '/cfg/rules',
  defaults : function() { return {}; },

});

var DCAFRuleList = Backbone.Collection.extend({

  initialize : function() {
    this.on('reset', this.testreset, this);
    this.on('add', this.testadd, this);
    this.on('remove', this.testremove, this);
    this.on('change', this.testchange, this);
  },

  // Reference to this collection's model.
  model : DCAFRule,
  url : '/cfg/rules',

  remaining : function() { return this.where({done : false}); },
  byId : function(fp) { return this.where({id : fp}); },
  testreset : function() { console.log("testreset"); },
  testadd : function() { console.log("testadd"); },
  testremove : function() { console.log("testremove"); },
  testchange : function() { console.log("testchange"); }

});

//
// DCAF Ticket
// Model and Collection
//
var DCAFTicket = Backbone.Model.extend({
  urlRoot : '/cfg/tickets',
  defaults : function() { return {}; },

});

var DCAFTicketList = Backbone.Collection.extend({

  initialize : function() {
    this.on('reset', this.testreset, this);
    this.on('add', this.testadd, this);
    this.on('remove', this.testremove, this);
    this.on('change', this.testchange, this);
  },

  // Reference to this collection's model.
  model : DCAFTicket,
  url : '/cfg/tickets',

  remaining : function() { return this.where({done : false}); },
  byId : function(fp) { return this.where({id : fp}); },
  testreset : function() { console.log("testreset"); },
  testadd : function() { console.log("testadd"); },
  testremove : function() { console.log("testremove"); },
  testchange : function() { console.log("testchange"); }

});

//
// DCAF Ticket Revocation
// Model and Collection
//
var DCAFRevocation = Backbone.Model.extend({
  urlRoot : '/cfg/revocations',
  idAttribute : 'id',
  defaults : function() { return {}; },

});

var DCAFRevocationList = Backbone.Collection.extend({

  initialize : function() {
    this.on('reset', this.testreset, this);
    this.on('add', this.testadd, this);
    this.on('remove', this.testremove, this);
    this.on('change', this.testchange, this);
  },

  // Reference to this collection's model.
  model : DCAFRevocation,
  url : '/cfg/revocations',
  remaining : function() { return this.where({done : false}); },
  byId : function(fp) { return this.where({id : fp}); },
  undelivered : function() { return this.where({delivery_time : 0}); },
  testreset : function() { console.log("testreset"); },
  testadd : function() { console.log("testadd"); },
  testremove : function() { console.log("testremove"); },
  testchange : function() { console.log("testchange"); }

});
