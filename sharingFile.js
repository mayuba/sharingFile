 var Uploads = new FS.Collection('uploads',{

    stores:[new FS.Store.FileSystem('uploads',{ path:'~/appdevoir2'})]
});

if (Meteor.isClient) {

    Template.hello.helpers({
        counter: function () {
            return Session.get('counter');
        },
        uploads:function(){

            return Uploads.find();
        }
    });

    Template.hello.events({

        'change .fileInput': function(event,template) {
            FS.Utility.eachFile(event, function(file){
                var fileObj = new FS.File(file);
                Uploads.insert(file,function(err){
                    console.log(err);
                })
            })
        }
    });

if (Meteor.isServer) {
    Meteor.startup(function () {
    });
}}
