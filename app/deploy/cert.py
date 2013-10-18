#!/bin/python

# dependencies - flask, flask-pymongo
# pip install Flask, Flask-PyMongo

#html/rest
from flask import Flask, jsonify, abort, make_response, request, render_template
# mail
import smtplib
from email.mime.text import MIMEText
import smtplib
import sys
import os
import hashlib
# data
from flask.ext.pymongo import PyMongo
import re
from bson import Binary, Code
from bson.json_util import dumps

import ConfigParser
config = ConfigParser.RawConfigParser()
configFile = os.path.dirname(__file__)+'config.cfg'
config.readfp(open(configFile))



tmpl_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'templates')

# name of app is also name of mongodb table

app = Flask("ndn_cert",template_folder=tmpl_dir)

mongo = PyMongo(app)

URL = "http://cert.ndn.ucla.edu:5000"


# return render_template('confirm.html', name=name)

@app.route('/ndn/auth/v1.1/debug', methods = ['GET'])
def get_tasks():
    all = mongo.db.users.find()
    all_str = ""
    for user in all:
        all_str+=str(user)+"\n"
    return (all_str)

@app.route('/ndn/auth/v1.1/users/', methods = ['GET'])
def get_user():
    user_email = request.args.get('email')
    ndn_name = request.args.get('ndn_name')
    user =  mongo.db.users.find_one({"email":user_email})
    if (user == None):
        #if user does not exist, make one
        user = {
            'email': user_email,
            'ndn-name': ndn_name,
            'pubkey': '', 
            'cert': '', #cert is base64 encoded binary
            'confirmed': False
        }
        #make a new one
        mongo.db.users.insert(user)
        mailUser(user)
        return("please check email")
    #if user exists, but is not confirmed
    elif(user['confirmed'] == False):
        #send confirmation email
        mailUser(user)
        return("please check email")
    # otherwise, user is confirmed, so let's just return that fact for now. 
    return jsonify( { 'confirmed': user['confirmed'],'email': user['email'],'NDNName': user['ndn-name'] } )
    
    
# this one has more fields than 1.2 (which just had email & ndn name)
@app.route('/ndn/auth/v1.2/users/', methods = ['GET'])
def get_user_and_metadata():
	#required parameters
    user_email = request.args.get('email')
    ndn_name = request.args.get('ndn_name')
    fullname = ndn_name = request.args.get('fullname')
    homeurl = ndn_name = request.args.get('homeurl')
    #optional parameters
    group = ""
    advisor = ""
    if 'group' in request.args:
    	group = ndn_name = request.args.get('group')    
    if 'advisor' in request.args:
    	advisor = request.args.get('advisor')    	
    user =  mongo.db.users.find_one({"email":user_email})
    if (user == None):
        #if user does not exist, make one
        user = {
            'email': user_email,
            'ndn-name': ndn_name,
            'pubkey': '', 
            'cert': '', #cert is base64 encoded binary
            'confirmed': False,
            'fullname': fullname,
            'homeurl': homeurl,
            'group': group,
            'advisor': advisor,
        }
        #make a new one
        mongo.db.users.insert(user)
        mailUser(user)
        return("please check email")
    #if user exists, but is not confirmed
    elif(user['confirmed'] == False):
        #send confirmation email
        mailUser(user)
        return("please check email")
    # otherwise, user is confirmed, so let's just return that fact for now. 
    return "user already in database. <br/>shall we still send an email, in case they want to update key? hmmm.<br/> meanwhile, debug: <br/> "+dumps( user )
    
@app.route('/ndn/auth/v1.1/validate/', methods = ['GET'])
def valid_email():
    user_email = request.args.get('email')
    token = request.args.get('token')
    user =  mongo.db.users.find_one_or_404({'email': user_email})
    # make token again, from database 
    m = hashlib.sha256()
    m.update(str(user['_id']))
    dbtoken = str(m.hexdigest())
    if(token==dbtoken):
        # yay, user is validated, update db thusly
        lastID = mongo.db.users.update({ '_id': user['_id'] },
                         {
                           "$set": { 'confirmed': True }
                         })
        return render_template('confirm.html', name=user['ndn-name'])
    #else just dump to browser for now
    return "token invalid. please try again; and write us at named-data.net if this is a problem."
    
    
@app.route('/ndn/auth/v1.1/pubkey/', methods = ['GET'])
def get_key():
    ndn_name = request.args.get('ndn_name')
    pubkey = request.args.get('pubkey')
    #return jsonify( { 'pubkey': pubkey, 'ndn_name':ndn_name } )
    last = mongo.db.users.update({ 'ndn-name': str(ndn_name) },
                     {
                       "$set": { 'pubkey': str(pubkey) }
                     })
    return "<pre> ok ! please wait up to 24 hours for operator approval.\n you will be emailed your signed .cert \n"+str(last)+"</pre>"
    
    
## NEW / 'final' operator routes

@app.route('/ndn/auth/v1.1/candidates/<string:inst_str>', methods = ['GET'])
def get_candidates(inst_str):
    # get all valid users containing 'institution_str'where cert=null
    all = mongo.db.users.find({'cert':'', 'confirmed':True, "ndn-name": {'$regex':inst_str}})
    all_str = ""
    for user in all:
        all_str+=str(user)+"<br/>"
    return (all_str)


@app.route('/ndn/auth/v1.1/candidates/<string:email>/addcert/<string:cert>', methods = ['GET'])
def write_cert(email, cert):
     # "denied" | cert_str
     ok = mongo.db.users.update({ 'email': email },{"$set": { 'cert': cert }})
     return str(ok)
     
     
# LEGACY DICT / NONMONGO

@app.route('/ndn/auth/v1.0/certs/<string:user_email>', methods = ['GET'])
def get_cert(user_email):
    user = filter(lambda t: t['email'] == user_email, users)
    if len(user) == 0:
        abort(404)
    return jsonify( { 'cert': user[0]['cert'],'email': user[0]['email'] } )

@app.route('/ndn/auth/v1.0/keys/<string:user_email>', methods = ['GET'])
def get_pubkey(user_email):
    user = filter(lambda t: t['email'] == user_email, users)
    if len(user) == 0:
        abort(404)
    return jsonify( { 'pubkey': user[0]['pubkey'],'email': user[0]['email'] } )




def mailUser(user):
    SERVER = "localhost"
    FROM = "cert@ndn.ucla.edu"
    TO = user['email']
    ndnname = user['ndn-name']

    SUBJECT = "Message From " + FROM
    m = hashlib.sha256()
    m.update(str(user['_id']))
    TEXT = 'please visit following URL to authorize your new NDN trust name, '+user['ndn-name']+'\n'
    TEXT += URL+'/ndn/auth/v1.1/validate/?email='+user['email']+'&token='+str(m.hexdigest())

    # Prepare actual message

    message = """\
    From: %s
    To: %s
    Subject: %s

    %s
    """ % (FROM, ", ".join(TO), SUBJECT, TEXT)

    # Send the mail

    server = smtplib.SMTP(SERVER)
    server.sendmail(FROM, TO, message)
    server.quit()

@app.errorhandler(404)
def not_found(error):
    return make_response(jsonify( { 'error': 'Not found' } ), 404)
    
# base64.b64decode(s)
# base64.b64encode(s)

if __name__ == '__main__':
    app.run(debug = True, host='0.0.0.0')