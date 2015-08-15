var base64Matcher = new RegExp("^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{4})$");

require([
  'libs/text!header.html',
  'libs/text!home.html',
  'libs/text!footer.html',
  'libs/text!subjects.html',
  'libs/text!addsubject.html',
  'libs/text!servers.html',
  'libs/text!addserver.html',
  'libs/text!addserver_resource.html',
  'libs/text!rules.html',
  'libs/text!addrule.html',
  'libs/text!addrule_resource.html',
  'libs/text!tickets.html',
  'libs/text!revocations.html',
  'libs/text!commissioning.html'
],
function(headerTpl, homeTpl, footerTpl, subjectsTpl, subjectAddTpl, serversTpl, serverAddTpl, serverAddResTpl, rulesTpl, addruleTpl, addRuleResourceTpl, ticketsTpl, revocationsTpl, commissioningTpl) {

  var subjects = new DCAFSubjectList;
  var servers = new DCAFServerList;
  var rules = new DCAFRuleList;
  var tickets = new DCAFTicketList;
  var revocations = new DCAFRevocationList;

  function refreshResources(cb) {


    if (cb) {
	    subjects.fetch({update : true, success: function() {
	    	servers.fetch({update : true, success: function() {
		    	rules.fetch({update : true, success: function() {
			    	tickets.fetch({update : true, success: function() {
				    	revocations.fetch({update : true, success: function() {
				    		cb();
				    	}});
			    	}});
		    	}});
	    	}});
	    }});
    }else {

	    subjects.fetch({update : true});
	    servers.fetch({update : true});
	    rules.fetch({update : true});
	    tickets.fetch({update : true});
	    revocations.fetch({update : true});
    }

  }

  function showContentView(v) {
  	$("#content .contentDiv").hide();
  	v.showView();
  }

  function samShowSuccess(msg, t) {
  	var ti = 1500;
  	if (t && t > 0) ti = t;
  	$(".sammsgsuccess").text(msg);
  	$(".sammsgsuccess").show();
  	setTimeout(function() {
	  	$(".sammsgsuccess").fadeOut( 1000, function() {
	    	$(".sammsgsuccess").hide();
	  	});
  	}, ti);
  }

  function samShowError(msg) {
  	$(".sammsgalert").text(msg);
  	$(".sammsgalert").show();
  	setTimeout(function() {
	  	$(".sammsgalert").fadeOut( 100, function() {
	    	$(".sammsgalert").hide();
	  	});
  	}, 1500);
  }

  setInterval(function() {
  	refreshResources();
  }, 5000);

  var ApplicationRouter = Backbone.Router.extend({
    routes : {
    	"addSubject": "addSubject",
    	"subjects": "showSubjects",
    	"editSubject/*fingerprint": "editSubject",
    	"deleteSubject/*fingerprint": "deleteSubject",

    	"server": "showServers",
    	"addServer": "addServer",
    	"editServer/*id": "editServer",
    	"deleteServer/*id": "deleteServer",

    	"rules": "showRules",
    	"deleteRule/*id": "deleteRule",
    	"addRule": "addRule",
    	"editRule/*id": "editRule",

    	"tickets": "showTickets",

    	"revocations": "showRevocations",
    	"addRevocation/*id": "addRevocation",

    	"commissioning": "showCommissioning",


    	"" : "home",
    	"*actions" : "home"
    },
    initialize : function() {
      this.headerView = new HeaderView();
      this.headerView.render();
      this.footerView = new FooterView();
      this.footerView.render();

	  this.homeView = new HomeView();

      this.subjectsView = new SubjectsView();
      this.addeditsubjectView = new AddEditSubjectView();

      this.serversView = new ServersView();
      this.addeditserverView = new AddEditServerView();

      this.rulesView = new RulesView();
      this.addeditruleView = new AddEditRuleView();

	  this.ticketsView = new TicketsView();

	  this.revocationsView = new RevocationsView();

	  this.commissioningView = new CommissioningView();





    },
    home : function() {
      //this.homeView.render();
      showContentView(this.homeView);
    },
    showSubjects: function() {
		//this.subjectsView.render();
		showContentView(this.subjectsView);
    },
    addSubject: function() {
    	this.addeditsubjectView.render(null);
    	showContentView(this.addeditsubjectView);
    },
    editSubject: function(fingerprint) {
    	this.addeditsubjectView.render(subjects.byFingerprint(fingerprint)[0]);
    	showContentView(this.addeditsubjectView);
    },
    deleteSubject: function(fingerprint) {
    	var ok = confirm("Permanently delete CAM?");
    	if (ok) {
    		var m = subjects.byFingerprint(fingerprint)[0];
    		subjects.remove(m);
    		m.destroy();
    		this.navigate("/subjects", true);
    	}
    },
    showServers: function() {
    	showContentView(this.serversView);
    },
    addServer: function() {
    	this.addeditserverView.render(null);
    	showContentView(this.addeditserverView);
    },
    editServer: function(id) {
    	this.addeditserverView.render(servers.byId(id)[0]);
    	showContentView(this.addeditserverView);
    	this.addeditserverView.addmodelforupdate(servers.byId(id)[0]);
    },
    deleteServer: function(id) {
    	var ok = confirm("Permanently delete Server?");
    	if (ok) {
    		var m = servers.byId(id)[0];
    		servers.remove(m);
    		m.destroy();
    		this.navigate("/server", true);
    	}
    },
    showRules: function() {
    	showContentView(this.rulesView);
    },
    deleteRule: function(id) {
    	var ok = confirm("Permanently delete Access Rule?");
    	if (ok) {
    		var m = rules.byId(id)[0];
    		rules.remove(m);
    		m.destroy();
    		this.navigate("/rules", true);
    	}
    },
    addRule: function() {
    	this.addeditruleView.render(null);
    	showContentView(this.addeditruleView);
    },
    editRule: function(id) {
    	this.addeditruleView.render(rules.byId(id)[0]);
    	showContentView(this.addeditruleView);
    	this.addeditruleView.addmodelforupdate(rules.byId(id)[0]);
    },
    showTickets: function() {
    	showContentView(this.ticketsView);
    },
    showRevocations: function() {
    	showContentView(this.revocationsView);
    },
    addRevocation: function(id) {
    	//alert(id);
    	var revocation = {
    		ticket: tickets.byId(id)[0].toJSON(),
		    delivery_time: 0,
		    last_try: 0,
		    tries: 0
    	}
        var snew = new DCAFRevocation(revocation);
        revocations.create(snew);
        this.navigate("/tickets", true);

    },
    showCommissioning: function() {
    	showContentView(this.commissioningView);
    },
  });


  HeaderView = Backbone.View.extend({
    el : "#header",
    templateFileName : "header.html", template : headerTpl,
    events: {
    	"click .fake_data_cam_lnk"    : "onCamClick",
    	"click .fake_data_server_lnk" : "onServerClick",
    	"click .fake_data_rule_lnk"   : "onRuleClick",
    	"click .fake_data_rule2_lnk"   : "onRule2Click",
    	"click .fake_data_commi_lnk"  : "onCommissioningClick"
    },
    initialize : function() {
      // $.get(this.templateFileName,
      // function(data){console.log(data);this.template=data});
      var self = this;
      Backbone.history.on("all", function(route, router) {
        var hash_nav = window.location.hash.split("/")[0].split("#")[1];
        self.$("#dcaf_nav_bar li").removeClass("active");
        self.$("#dcaf_nav_" + hash_nav).addClass("active");

        self.$(".fakeheaderdrop li").hide();
        var i = 0;
        if (hash_nav == "addSubject") {
        	self.$(".fake_data_cam_lnk").parent().show();
        	i++;
        }
        if (hash_nav == "addServer") {
        	self.$(".fake_data_server_lnk").parent().show();
        	i++;
        }
        if (hash_nav == "addRule") {

        	self.$(".fake_data_rule_lnk").parent().show();
        	self.$(".fake_data_rule2_lnk").parent().show();
        	self.$(".fake_data_rule2_lnk").parent().prev().show();
        	i+=2;
        }
        if (hash_nav == "commissioning") {
        	self.$(".fake_data_commi_lnk").parent().show();
        	i++;
        }


        self.$("#headerSzenarioBadge").text(i);

        if (i == 0) {
        	self.$(".bananadrop").hide();
        } else {
        	self.$(".bananadrop").show();
        }

      });

    },
    render : function() { $(this.el).html(_.template(this.template)); },
    onCamClick: function() {
    	app.addeditsubjectView.$(".sam_form_subject_name").val("Transportunternehmen 1");
    	app.addeditsubjectView.$(".sam_form_subject_fingerprint").val("mJ6N/FQ55PDPfi0WqMzf3W2uWgk=");
    },
    onServerClick: function() {
    	app.addeditserverView.$(".sam_form_server_id").val("aaaa::200:0:0:2");
    	app.addeditserverView.$(".sam_form_server_secret").val("2NUH+rjrEUGxFywoYSpWBQ==");
    	app.addeditserverView.$(".addserver_resource_btn").click();
    	app.addeditserverView.$(".sam_form_server_res_uri").val("temp/1");
    	app.addeditserverView.$(".checkbxGet").prop('checked', true);
    },
    onRuleClick: function() {
    	app.addeditruleView.$(".sam_form_rule_id").val("Transportregel 1");
    	app.addeditruleView.$(".sam_form_rule_cam").val("mJ6N/FQ55PDPfi0WqMzf3W2uWgk=");

    	app.addeditruleView.$(".addserver_resource_btn").click();
    	app.addeditruleView.$(".sam_form_server_res_server").val("aaaa::200:0:0:2");
    	app.addeditruleView.$(".sam_form_server_res_uri").val("*");
    	app.addeditruleView.$(".checkbxGet").prop('checked', true);
    	app.addeditruleView.$(".checkbxPost").prop('checked', true);
    	app.addeditruleView.$(".checkbxPut").prop('checked', true);
    	app.addeditruleView.$(".checkbxDelete").prop('checked', true);
    },
    onRule2Click: function() {
    	app.addeditruleView.$(".sam_form_rule_id").val("Transportregel 2");
    	app.addeditruleView.$(".sam_form_rule_cam").val("mJ6N/FQ55PDPfi0WqMzf3W2uWgk=");

    	app.addeditruleView.$(".addserver_resource_btn").click();
    	app.addeditruleView.$(".sam_form_server_res_server").val("aaaa::200:0:0:2");
    	app.addeditruleView.$(".sam_form_server_res_uri").val("temp/1");
    	app.addeditruleView.$(".checkbxGet").prop('checked', true);
    },
    onCommissioningClick: function() {
    	app.commissioningView.$(".sam_form_com_sam").val("https://[aaaa::1]:8080/ep");
    	app.commissioningView.$(".sam_form_com_server").val("coaps://[aaaa::200:0:0:2]:5684/key");
    	app.commissioningView.$(".sam_form_com_key").val("2NUH+rjrEUGxFywoYSpWBQ==");
    	app.commissioningView.$(".sam_form_com_ticket").val('{"id": "wLjOzOa2ZbZWWQ==", "face": {"conditions": [], "AI": [{"rs": "aaaa::200:0:0:2", "resource": "temp/1", "methods": 1}], "sequence_number": 0, "timestamp": 1000, "dtls_psk_gen_method": 0, "lifetime": 3600}, "verifier_size": 16, "verifier": "Hx51eWCUG7QCxgs1nJXezg=="}');
    },
  });

  FooterView = Backbone.View.extend({
    el : "#footer",
    template : footerTpl,
    render : function() { this.$el.html(_.template(this.template)); }
  });

  HomeView = Backbone.View.extend({
    tagName: "div",
    className: "contentDiv",
    // template: "home.html",
    template : homeTpl,
    initialize : function() {
    	$("#content").append(this.el);
    	this.render();
    },
    render : function() { $(this.el).html(_.template(this.template)); },
    showView: function() { $(this.el).show(); }
  });



  var SubjectsView = Backbone.View.extend({
    template : $("#layoutTpl").html(),
    events: {
    	//"click .sam_table_row" : "onClickSubjectRow"
    },

    initialize : function() {
    	this.collection = subjects;
		this.listenTo(this.collection,'all', this.render);
		$("#content").append(this.el);
		this.render();
    },
    render : function() { $(this.el).html(_.template(this.template, {collection: this.collection.toJSON()})); },
    showView: function() { $(this.el).show(); },
    onClickSubjectRow: function() {alert("klick")}
  });


  var AddEditSubjectView = Backbone.View.extend({
    tagName: "div",
    className: "contentDiv",
    template : subjectAddTpl,

    events: {
    	"click .samformsubmit" : "onClickAddSubject"
    },
    initialize : function() {
		$("#content").append(this.el);
    },
    render : function(subjectmodel) {
    	if (subjectmodel !== null) {
			$(this.el).html(_.template(this.template, {word: "Update", sub: subjectmodel.toJSON()}));
    	} else {
			$(this.el).html(_.template(this.template, {word:"Add", sub:{name:"", cert_fingerprint:""}}));
    	}
    },
    showView: function() {
    	$(this.el).show();
    },
    onClickAddSubject: function() {
    	var formdata = {
    		cert_fingerprint: this.$(".sam_form_subject_fingerprint").val().trim(),
    		name: this.$(".sam_form_subject_name").val().trim(),
    	}

    	var b64length = 0;
		try {
		    var b64 = window.atob(formdata.cert_fingerprint);
  			b64length = b64.length;
		} catch(e) {}

		if (b64length !== 20) {
			samShowError("Thats not a Base64 or SHA1-Fingerprint")
			return;
		}



		var m = subjects.byFingerprint(formdata.cert_fingerprint);
		if (m.length === 0) {
			samShowSuccess("CAM added");
            var snew = new DCAFSubject(formdata);
            subjects.create(snew);
            app.navigate("/subjects", true);
		} else {
			samShowSuccess("CAM changed");
			m[0].set(formdata);
			m[0].save();
			app.navigate("/subjects", true);
		}
    }
  });




  var ServersView = Backbone.View.extend({
    //el : "#content",
    tagName: "div",
    className: "contentDiv",
    template : serversTpl,
    events: {
    	//"click .sam_table_row" : "onClickSubjectRow"
    },

    initialize : function() {
    	this.collection = servers;
		this.listenTo(this.collection,'all', this.render);
		$("#content").append(this.el);
		this.render();
    },
    render : function() { $(this.el).html(_.template(this.template, {collection: this.collection.toJSON()})); },
    showView: function() { $(this.el).show(); },
    onClickSubjectRow: function() {alert("klick")}
  });




  var AddEditServerView = Backbone.View.extend({
    tagName: "div",
    className: "contentDiv",
    template : serverAddTpl,

    events: {
    	"click .samformsubmit" : "onClickAddServer",
    	"click .addserver_resource_btn": "onAddResource",
    	"click .addserverresdelbtn": "onDelRes"
    },
    initialize : function() {
		$("#content").append(this.el);
    },
    render : function(servermodel) {
    	if (servermodel !== null) {
			$(this.el).html(_.template(this.template, {word: "Update", sub: servermodel.toJSON()}));
    	} else {
			$(this.el).html(_.template(this.template, {word:"Add", sub:{secret: "",id: "",last_seq_nr: 0,conditions: [],resources: [],rs_state_lowest_seq: 0}}));
    	}
    },
    showView: function() {
    	$(this.el).show();
    },
    onClickAddServer: function() {
    	var formdata = {
    		id: this.$(".sam_form_server_id").val().trim(),
    		secret: this.$(".sam_form_server_secret").val().trim(),
			last_seq_nr: 0,
			rs_state_lowest_seq: 0,
    		resources: [],
    		conditions: []
    	}

    	var m = servers.get(formdata.id);

    	if (formdata.secret === "***") {
    		formdata.secret = m.get("secret");
    	}

		try {
		   window.atob(formdata.secret);
		} catch(e) {
				samShowError("Invalid Secret. Please enter base64 encoded data");
				return;
		}

    	$.each(this.$(".sam_form_server_conditions").val().split(","), function( index, value ) {
    		value = value.trim();
    		if (value)
    			formdata.conditions.push({key:value});
    	});

    	var success = true;
		$.each(this.$(".addserverresourcediv"), function( index, value ) {
			res = {
				resource: $(".sam_form_server_res_uri", value).val().trim(),
				methods: 0
			};
			if (res.resource[0] === "/") {
				res.resource = res.resource.substr(1, res.length);
			}
			if ($('.checkbxGet', value).is(':checked')) {
				res.methods += 1;
			}
			if ($('.checkbxPost', value).is(':checked')) {
				res.methods += 2;
			}
			if ($('.checkbxPut', value).is(':checked')) {
				res.methods += 4;
			}
			if ($('.checkbxDel', value).is(':checked')) {
				res.methods += 8;
			}

			if (!res.resource) {
				samShowError("Please enter an URI");
				success = false;
				return;
			}

			formdata.resources.push(res);
		});

		if (!success || !formdata.id || !formdata.secret || formdata.resources.length === 0) {
			samShowError("Field/s missing");
			return;
		}


		if (!m) {
			samShowSuccess("Server added");
	        var snew = new DCAFServer(formdata);
	        servers.create(snew);
	        app.navigate("/server", true);
		} else {
			samShowSuccess("Server changed");
			m.set(formdata);
			m.save();
			app.navigate("/server", true);
		}



    },
    addmodelforupdate: function(servermodel) {
    	var self = this;
    	$.each(servermodel.get("resources"), function( index, res ) {
    		self.$(".addserver_resource_container").append(_.template(serverAddResTpl, {res:res}));
    	});
    	var condval = "";
    	$.each(servermodel.get("conditions"), function( index, cond ) {
    		condval += cond.key += ", ";
    	});
    	self.$(".sam_form_server_conditions").val(condval.substr(0, condval.length-2));
    },
    onAddResource: function(e) {
    	this.$(".addserver_resource_container").append(_.template(serverAddResTpl, {res:{}}));
    },
    onDelRes: function(e) {
    	$(e.currentTarget).parent().parent().parent().parent().remove();
    }
  });


  var RulesView = Backbone.View.extend({
    //el : "#content",
    tagName: "div",
    className: "contentDiv",
    template : rulesTpl,
    events: {
    	//"click .sam_table_row" : "onClickSubjectRow"
    },

    initialize : function() {
    	this.collection = rules;
		this.listenTo(this.collection,'all', this.render);
		$("#content").append(this.el);
		this.render();
    },
    render : function() { $(this.el).html(_.template(this.template, {collection: this.collection.toJSON(), subjects:subjects, date: Date})); },
    showView: function() { $(this.el).show(); },
  });


  var AddEditRuleView = Backbone.View.extend({
    tagName: "div",
    className: "contentDiv",
    template : addruleTpl,

    events: {
    	"click .samformsubmit" : "onClickAddRule",
    	"click .addserver_resource_btn": "onAddResource",
    	"click .addserverresdelbtn": "onDelRes",
    	"change .sam_form_server_res_server": "onChangeResourceServer"
    },
    initialize : function() {
		$("#content").append(this.el);
    },
    render : function(rulemodel) {
    	if (rulemodel !== null) {
			$(this.el).html(_.template(this.template, {word: "Update", subjects:subjects.toJSON(), sub: rulemodel.toJSON()}));
    	} else {
			$(this.el).html(_.template(this.template, {word:"Add", subjects:subjects.toJSON(), sub:{id: "",subject: "",resources: [],conditions: [],expiration_time: 0,priority: 0}}));
    	}
    },
    showView: function() {
    	$(this.el).show();
    },
    onClickAddRule: function() {
    	var method = "update";
    	if (!this.$(".sam_form_rule_id").attr("disabled")) {
    		method = "add"
    	}

    	var formdata = {
    		id: this.$(".sam_form_rule_id").val().trim(),
    		subject: this.$(".sam_form_rule_cam").val().trim(),
			expiration_time: this.$(".sam_form_rule_expiration_date").val().trim(),
			priority: parseInt(this.$(".sam_form_rule_priority").val().trim()),
    		resources: [],
    		conditions: []
    	}


		if (!formdata.subject || formdata.subject === "") {
				samShowError("Choose CAM!");
				return;
		}

		try {
		   window.atob(formdata.subject);
		} catch(e) {
				samShowError("Invalid CAM!");
				return;
		}

		if (formdata.expiration_time === "" || formdata.expiration_time  === "0") {
			formdata.expiration_time = 0;
		}
		else {
			formdata.expiration_time  = new Date(formdata.expiration_time).getTime()/1000;

			if (!formdata.expiration_time || formdata.expiration_time < new Date().getTime()/1000) {
				samShowError("Expiration date invalid or in the past");
				return;
			}
		}



		if (formdata.id === "") {
				samShowError("Invalid Name!");
				return;
		}



		var a = rules.get(formdata.id);
		if (method === "add") {
			if (a) {
				samShowError("Name already taken!");
				return;
			}
		} else {
			if (!a) {
				samShowError("Name not found!");
				return;
			}
		}


		var condition_str = this.$(".sam_form_server_conditions").val().trim();
		if (condition_str !== "") {
			var c = "";
			try {
				c = JSON.parse(condition_str);
			}
			catch(e) {
				samShowError("Invalid Condition");
				return;
			}

			if (c !== "" && !jQuery.isArray( c )) {
				samShowError("Invalid Condition");
				return;
			}
		}

    	var success = true;
		$.each(this.$(".addserverresourcediv"), function( index, value ) {
			res = {
				rs: $(".sam_form_server_res_server", value).val().trim(),
				resource: $(".sam_form_server_res_uri", value).val().trim(),
				methods: 0
			};
			if (res.resource[0] === "/") {
				res.resource = res.resource.substr(1, res.length);
			}
			if ($('.checkbxGet', value).is(':checked')) {
				res.methods += 1;
			}
			if ($('.checkbxPost', value).is(':checked')) {
				res.methods += 2;
			}
			if ($('.checkbxPut', value).is(':checked')) {
				res.methods += 4;
			}
			if ($('.checkbxDel', value).is(':checked')) {
				res.methods += 8;
			}

			if (!res.rs) {
				samShowError("Please choose a Server");
				success = false;
				return;
			}

			if (!res.resource) {
				samShowError("Please enter an URI");
				success = false;
				return;
			}

			formdata.resources.push(res);
		});

		if (!success || formdata.resources.length === 0) {
			samShowError("Field/s missing");
			return;
		}


		if (method === "add") {
			samShowSuccess("Rule added");
	        var snew = new DCAFRule(formdata);
	        rules.create(snew);
	        app.navigate("/rules", true);
		} else {
			samShowSuccess("Rule changed");
			a.set(formdata);
			a.save();
			if ($('.checkbxrevoke').is(':checked')) {

				tickets.each(function(tick) {
			    	var revocation = {
			    		ticket: tick.toJSON(),
					    delivery_time: 0,
					    last_try: 0,
					    tries: 0
			    	}
			        var snew = new DCAFRevocation(revocation);
			        revocations.create(snew);
		    	});


			}

			app.navigate("/rules", true);
		}
    },
    addmodelforupdate: function(servermodel) {
    	var self = this;
    	self.$(".sam_form_rule_cam").val(servermodel.get("subject"));
    	var ex = servermodel.get("expiration_time");
    	if (ex !== 0) {
    		var d = new Date(ex*1000).format("yyyy-HH-mm'T'mm:ss");
    		self.$(".sam_form_rule_expiration_date").val(d);

    	}

    	$.each(servermodel.get("resources"), function( index, res ) {
    		self.$(".addserver_resource_container").append(_.template(addRuleResourceTpl, {res:res, servers:servers.toJSON()}));
    		$(".sam_form_server_res_server", self.$(".addserver_resource_container").children().last()).val(res.rs);

    		$(".sam_form_server_res_server", self.$(".addserver_resource_container").children().last()).change();
    		$(".sam_form_server_res_uri", self.$(".addserver_resource_container").children().last()).val(res.resource);
    	});
    	var condval = "";
    	$.each(servermodel.get("conditions"), function( index, cond ) {
    		condval += cond.key += ", ";
    	});
    	self.$(".sam_form_server_conditions").val(condval.substr(0, condval.length-2));
    },
    onAddResource: function(e) {
    	this.$(".addserver_resource_container").append(_.template(addRuleResourceTpl, {res:{}, servers:servers.toJSON()}));
    	$(".sam_form_server_res_server", this.$(".addserver_resource_container").children().last()).change();
    },
    onDelRes: function(e) {
    	$(e.currentTarget).parent().parent().parent().parent().remove();
    },
    onChangeResourceServer: function(e) {
    	var options = '<option value="*">All Resources</option>';
    	var srv = servers.byId($(e.currentTarget).val().trim())[0];

    	$.each(srv.get("resources"), function( index, r ) {
    		options += '<option value="'+r.resource+'">/'+r.resource+'</option>';
    	});
    	var sel = $(".sam_form_server_res_uri", $(e.currentTarget).parent().parent().next().children());
    	sel.html(options);
    }
  });


  var TicketsView = Backbone.View.extend({
    tagName: "div",
    className: "contentDiv",
    template : ticketsTpl,
    events: {
    },

    initialize : function() {
    	this.collection = tickets;
		this.listenTo(this.collection,'all', this.render);
		$("#content").append(this.el);
		this.render();
    },
    render : function() { $(this.el).html(_.template(this.template, {collection: this.collection.toJSON()})); },
    showView: function() { $(this.el).show(); },
    onClickSubjectRow: function() {alert("klick")}
  });

  var RevocationsView = Backbone.View.extend({
    tagName: "div",
    className: "contentDiv",
    template : revocationsTpl,
    events: {
    },

    initialize : function() {
    	this.collection = revocations;
		this.listenTo(this.collection,'all', this.render);
		$("#content").append(this.el);
		this.render();
    },
    render : function() {
    	$(this.el).html(_.template(this.template, {collection: this.collection.toJSON(), date:Date}));
    	var undelivered = this.collection.undelivered().length;
    	if (undelivered > 0) {
    		$("#headerRevocBadge").text(undelivered);
    	}
    },
    showView: function() { $(this.el).show(); },
    onClickSubjectRow: function() {alert("klick")}
  });


  var CommissioningView = Backbone.View.extend({
    tagName: "div",
    className: "contentDiv",
    template : commissioningTpl,
    events: {
    	"click .samformsubmit" : "onStartCommissioning",
    },

    initialize : function() {
  		$("#content").append(this.el);
  		this.render();
    },
    render : function() { $(this.el).html(_.template(this.template)); },
    showView: function() { $(this.el).show(); },
    onStartCommissioning: function() {
    	var formdata = {
    		new_sam: this.$(".sam_form_com_sam").val().trim(),
    		server_uri: this.$(".sam_form_com_server").val().trim(),
			new_key: this.$(".sam_form_com_key").val().trim(),
			ticket: this.$(".sam_form_com_ticket").val().trim()
    	}

		if (!formdata.new_sam || formdata.new_sam === "" || !formdata.server_uri || formdata.server_uri === "" ||
			!formdata.new_key || formdata.new_key === "" || !formdata.ticket || formdata.ticket === "") {
				samShowError("Field/s missing");
				return;
		}
		try {
		   formdata.ticket = JSON.parse(formdata.ticket);
		} catch(e) {
			samShowError("Invalid Ticket!");
			return;
		}
		$("#overlaydiv").show();

		jQuery.ajax({
	        type: "POST",
	        url: "/cfg/commissioning",
	        data: JSON.stringify(formdata),
	        error: function(a, b) {
	        	if (b === "error") {
					$("#overlaydiv").hide();
					samShowError("Error! Can't connect to Server!");
	        	} else {
					$("#overlaydiv").hide();
					samShowSuccess("Commissioning Successful! You can now add the new Server", 5000);
					app.navigate("/addServer", true);
					$(".fake_data_server_lnk").click();
	        	}

			},
	        dataType: "json",
	        contentType: "application/json",
	        processData: false
		});
    }
  });


  app = new ApplicationRouter();
  refreshResources(function() {
  	Backbone.history.start();
  });
});



/*
 * Date Format 1.2.3
 * (c) 2007-2009 Steven Levithan <stevenlevithan.com>
 * MIT license
 *
 * Includes enhancements by Scott Trenda <scott.trenda.net>
 * and Kris Kowal <cixar.com/~kris.kowal/>
 *
 * Accepts a date, a mask, or a date and a mask.
 * Returns a formatted version of the given date.
 * The date defaults to the current date/time.
 * The mask defaults to dateFormat.masks.default.
 */

var dateFormat = function () {
    var token = /d{1,4}|m{1,4}|yy(?:yy)?|([HhMsTt])\1?|[LloSZ]|"[^"]*"|'[^']*'/g,
        timezone = /\b(?:[PMCEA][SDP]T|(?:Pacific|Mountain|Central|Eastern|Atlantic) (?:Standard|Daylight|Prevailing) Time|(?:GMT|UTC)(?:[-+]\d{4})?)\b/g,
        timezoneClip = /[^-+\dA-Z]/g,
        pad = function (val, len) {
            val = String(val);
            len = len || 2;
            while (val.length < len) val = "0" + val;
            return val;
        };

    // Regexes and supporting functions are cached through closure
    return function (date, mask, utc) {
        var dF = dateFormat;

        // You can't provide utc if you skip other args (use the "UTC:" mask prefix)
        if (arguments.length == 1 && Object.prototype.toString.call(date) == "[object String]" && !/\d/.test(date)) {
            mask = date;
            date = undefined;
        }

        // Passing date through Date applies Date.parse, if necessary
        date = date ? new Date(date) : new Date;
        if (isNaN(date)) throw SyntaxError("invalid date");

        mask = String(dF.masks[mask] || mask || dF.masks["default"]);

        // Allow setting the utc argument via the mask
        if (mask.slice(0, 4) == "UTC:") {
            mask = mask.slice(4);
            utc = true;
        }

        var _ = utc ? "getUTC" : "get",
            d = date[_ + "Date"](),
            D = date[_ + "Day"](),
            m = date[_ + "Month"](),
            y = date[_ + "FullYear"](),
            H = date[_ + "Hours"](),
            M = date[_ + "Minutes"](),
            s = date[_ + "Seconds"](),
            L = date[_ + "Milliseconds"](),
            o = utc ? 0 : date.getTimezoneOffset(),
            flags = {
                d:    d,
                dd:   pad(d),
                ddd:  dF.i18n.dayNames[D],
                dddd: dF.i18n.dayNames[D + 7],
                m:    m + 1,
                mm:   pad(m + 1),
                mmm:  dF.i18n.monthNames[m],
                mmmm: dF.i18n.monthNames[m + 12],
                yy:   String(y).slice(2),
                yyyy: y,
                h:    H % 12 || 12,
                hh:   pad(H % 12 || 12),
                H:    H,
                HH:   pad(H),
                M:    M,
                MM:   pad(M),
                s:    s,
                ss:   pad(s),
                l:    pad(L, 3),
                L:    pad(L > 99 ? Math.round(L / 10) : L),
                t:    H < 12 ? "a"  : "p",
                tt:   H < 12 ? "am" : "pm",
                T:    H < 12 ? "A"  : "P",
                TT:   H < 12 ? "AM" : "PM",
                Z:    utc ? "UTC" : (String(date).match(timezone) || [""]).pop().replace(timezoneClip, ""),
                o:    (o > 0 ? "-" : "+") + pad(Math.floor(Math.abs(o) / 60) * 100 + Math.abs(o) % 60, 4),
                S:    ["th", "st", "nd", "rd"][d % 10 > 3 ? 0 : (d % 100 - d % 10 != 10) * d % 10]
            };

        return mask.replace(token, function ($0) {
            return $0 in flags ? flags[$0] : $0.slice(1, $0.length - 1);
        });
    };
}();

// Some common format strings
dateFormat.masks = {
    "default":      "ddd mmm dd yyyy HH:MM:ss",
    shortDate:      "m/d/yy",
    mediumDate:     "mmm d, yyyy",
    longDate:       "mmmm d, yyyy",
    fullDate:       "dddd, mmmm d, yyyy",
    shortTime:      "h:MM TT",
    mediumTime:     "h:MM:ss TT",
    longTime:       "h:MM:ss TT Z",
    isoDate:        "yyyy-mm-dd",
    isoTime:        "HH:MM:ss",
    isoDateTime:    "yyyy-mm-dd'T'HH:MM:ss",
    isoUtcDateTime: "UTC:yyyy-mm-dd'T'HH:MM:ss'Z'"
};

// Internationalization strings
dateFormat.i18n = {
    dayNames: [
        "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat",
        "Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"
    ],
    monthNames: [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
        "January", "February", "March", "April", "May", "June", "July", "August", "September", "October", "November", "December"
    ]
};

// For convenience...
Date.prototype.format = function (mask, utc) {
    return dateFormat(this, mask, utc);
};
