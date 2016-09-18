#!/usr/bin/env python

# Copyright (c) 2014  Regents of the University of California
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

# dependencies - flask, flask-pymongo
# pip install Flask, Flask-PyMongo

#html/rest
from flask import Flask, jsonify, abort, make_response, request, render_template
from flask.ext.pymongo import PyMongo
from flask.ext.mail import Mail, Message

# mail
import smtplib
from email.mime.text import MIMEText
import smtplib
import os
import string
import random
import datetime
import base64
import pyndn as ndn
import json
import urllib.parse

from bson import json_util
from bson.objectid import ObjectId

tmpl_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'templates')

# name of app is also name of mongodb "database"
app = Flask("ndncert", template_folder=tmpl_dir)
app.config.from_pyfile('%s/settings.py' % os.path.dirname(os.path.abspath(__file__)))
mongo = PyMongo(app)
mail = Mail(app)

app.mongo = mongo
app.mail = mail

from admin import admin
from cert import cert
app.register_blueprint(admin)
app.register_blueprint(cert)

#############################################################################################
# User-facing components
#############################################################################################

@app.route('/', methods = ['GET'])
@app.route('/tokens/request/', methods = ['GET', 'POST'])
def request_token():
    if request.method == 'GET':
        #################################################
        ###              Token request                ###
        #################################################

        guestSites = mongo.db.operators.find({'allowGuests':True})
        return render_template('token-request-form.html', URL=app.config['URL'], sites=guestSites)

    else: # 'POST'
        #################################################
        ###        Token creation & emailing          ###
        #################################################

        user_email = request.form['email']
        site_prefix = request.form['site']
        if site_prefix != "":
            params = get_operator_for_guest_site(user_email, site_prefix)
            try:
                params = get_operator_for_guest_site(user_email, site_prefix)
            except:
                return render_template('error-unknown-site.html')
        else:
            try:
                # pre-validation
                params = get_operator_for_email(user_email)
            except:
                return render_template('error-unknown-site.html')

        token = {
            'email': user_email,
            'token': generate_token(),
            'site_prefix': site_prefix,
            'created_on': datetime.datetime.utcnow(), # to periodically remove unverified tokens
            }
        mongo.db.tokens.insert(token)

        if params['domain'] == 'operators.named-data.net':
            return render_template('token-email.html', URL=app.config['URL'], **token)
        else:
            msg = Message("[NDN Certification] Request confirmation",
                          sender = app.config['MAIL_FROM'],
                          recipients = [user_email],
                          body = render_template('token-email.txt', URL=app.config['URL'], **token),
                          html = render_template('token-email.html', URL=app.config['URL'], **token))
            mail.send(msg)
            return render_template('token-sent.html', email=user_email)

@app.route('/help', methods = ['GET'])
def show_help():
    return render_template('how-it-works.html')

@app.route('/cert-requests/submit/', methods = ['GET', 'POST'])
def submit_request():
    if request.method == 'GET':
        # Email and token (to authorize the request==validate email)
        user_email = request.args.get('email')
        user_token = request.args.get('token')

        token = mongo.db.tokens.find_one({'email':user_email, 'token':user_token})
        if (token == None):
            abort(403)

        site_prefix = token['site_prefix']
        if site_prefix != "":
            try:
                params = get_operator_for_guest_site(user_email, site_prefix)
            except:
                abort(403)
        else:
            # infer parameters from email
            try:
                # pre-validation
                params = get_operator_for_email(user_email)
            except:
                abort(403)

        # don't delete token for now, just give user a form to input stuff
        return render_template('request-form.html', URL=app.config['URL'],
                               email=user_email, token=user_token, **params)

    else: # 'POST'
        # Email and token (to authorize the request==validate email)
        user_email = request.form['email']
        user_token = request.form['token']

        token = mongo.db.tokens.find_one({'email':user_email, 'token':user_token})
        if (token == None):
            abort(403)

        # Now, do basic validation of correctness of user input, save request in the database
        # and notify the operator
        #optional parameters

        user_fullname = request.form['fullname'] if 'fullname' in request.form else ""
        user_homeurl   = request.form['homeurl'] if 'homeurl' in request.form else ""
        user_group   = request.form['group']   if 'group'   in request.form else ""
        user_advisor = request.form['advisor'] if 'advisor' in request.form else ""

        site_prefix = token['site_prefix']
        if site_prefix != "":
            try:
                params = get_operator_for_guest_site(user_email, site_prefix)
            except:
                abort(403)
        else:
            # infer parameters from email
            try:
                # pre-validation
                params = get_operator_for_email(user_email)
            except:
                abort(403)

        if site_prefix == "" and user_fullname == "":
            return render_template('request-form.html',
                                   error="Full Name field cannot be empty",
                                   URL=app.config['URL'], email=user_email,
                                   token=user_token, **params)

        try:
            user_cert_request = base64.b64decode(request.form['cert-request'])
            user_cert_data = ndn.Data()
            # user_cert_data.wireDecode(ndn.Blob(buffer(user_cert_request)))
            user_cert_data.wireDecode(ndn.Blob(memoryview(user_cert_request)))
        except:
            return render_template('request-form.html',
                                   error="Incorrectly generated NDN certificate request, "
                                         "please try again",
                                   URL=app.config['URL'], email=user_email,
                                   token=user_token, **params)

        # check if the user supplied correct name for the certificate request
        if not params['assigned_namespace'].isPrefixOf(user_cert_data.getName()):
            return render_template('request-form.html',
                                   error="Incorrectly generated NDN certificate request, "
                                         "please try again",
                                   URL=app.config['URL'], email=user_email,
                                   token=user_token, **params)

        # cert_name = extract_cert_name(user_cert_data.getName()).toUri()
        # # remove any previous requests for the same certificate name
        # mongo.db.requests.remove({'cert_name': cert_name})

        cert_request = {
                'operator_id': str(params['operator']['_id']),
                'site_prefix': token['site_prefix'],
                'assigned_namespace': str(params['assigned_namespace']),
                'fullname': user_fullname,
                'organization': params['operator']['site_name'],
                'email': user_email,
                'homeurl': user_homeurl,
                'group': user_group,
                'advisor': user_advisor,
                'cert_request': base64.b64encode(user_cert_request),
                'created_on': datetime.datetime.utcnow(), # to periodically remove unverified tokens
            }
        mongo.db.requests.insert(cert_request)

        # OK. authorized, proceed to the next step
        mongo.db.tokens.remove(token)

        msg = Message("[NDN Certification] User certification request",
                      sender = app.config['MAIL_FROM'],
                      recipients = [params['operator']['email']],
                      body = render_template('operator-notify-email.txt', URL=app.config['URL'],
                                             operator_name=params['operator']['name'],
                                             **cert_request),
                      html = render_template('operator-notify-email.html', URL=app.config['URL'],
                                             operator_name=params['operator']['name'],
                                             **cert_request))
        mail.send(msg)

        return render_template('request-thankyou.html')

#############################################################################################
# Operator-facing components
#############################################################################################

@app.route('/cert-requests/get/', methods = ['POST'])
def get_candidates():
    commandInterestName = ndn.Name()
    commandInterestName.wireDecode(
        # ndn.Blob(buffer(base64.b64decode(request.form['commandInterest']))))
        ndn.Blob(base64.b64decode(request.form['commandInterest'])))

    site_prefix = ndn.Name()
    site_prefix.wireDecode(commandInterestName[-3].getValue().toBuffer())
    timestamp  = commandInterestName[-4]

    signature = ndn.WireFormat.getDefaultWireFormat().decodeSignatureInfoAndValue(commandInterestName[-2].getValue().toBuffer(),
                                                                                  commandInterestName[-1].getValue().toBuffer())
    keyLocator = signature.getKeyLocator().getKeyName()

    operator = mongo.db.operators.find_one({'site_prefix': site_prefix.toUri()})
    if operator == None:
        abort(403)

    # @todo Command Interest verificateion

    requests = mongo.db.requests.find({'operator_id': str(operator['_id'])})
    output = []
    for req in requests:
        output.append(req)

    # return json.dumps (output)
    return json.dumps(output, default=json_util.default)

@app.route('/cert/submit/', methods = ['POST'])
def submit_certificate():
    data = ndn.Data()
    # data.wireDecode(ndn.Blob(buffer(base64.b64decode(request.form['data']))))
    data.wireDecode(ndn.Blob(memoryview(base64.b64decode(request.form['data']))))

    cert_request = mongo.db.requests.find_one({'_id': ObjectId(str(request.form['id']))})
    if cert_request == None:
        abort(403)

    operator = mongo.db.operators.find_one({"_id": ObjectId(cert_request['operator_id'])})
    if operator == None:
        mongo.db.requests.remove(cert_request) # remove invalid request
        abort(403)

    # # @todo verify data packet
    # # @todo verify timestamp

    if len(data.getContent()) == 0:
        # (no deny reason for now)
        # eventually, need to check data.type: if NACK, then content contains reason for denial
        #                                      if KEY, then content is the certificate

        msg = Message("[NDN Certification] Rejected certification",
                      sender = app.config['MAIL_FROM'],
                      recipients = [cert_request['email']],
                      body = render_template('cert-rejected-email.txt',
                                             URL=app.config['URL'], **cert_request),
                      html = render_template('cert-rejected-email.html',
                                             URL=app.config['URL'], **cert_request))
        mail.send(msg)

        mongo.db.requests.remove(cert_request)

        return "OK. Certificate has been denied"
    else:
        cert = {
            'name': data.getName().toUri(),
            'cert': request.form['data'],
            'operator': operator,
            'created_on': datetime.datetime.utcnow(), # to periodically remove unverified tokens
            }
        mongo.db.certs.insert(cert)

        msg = Message("[NDN Certification] NDN certificate issued",
                      sender = app.config['MAIL_FROM'],
                      recipients = [cert_request['email']],
                      body = render_template('cert-issued-email.txt',
                                             URL=app.config['URL'],
                                             quoted_cert_name=urllib.parse.quote(cert['name'], ''),
                                             cert_id=str(data.getName()[-3]),
                                             **cert_request),
                      html = render_template('cert-issued-email.html',
                                             URL=app.config['URL'],
                                             quoted_cert_name=urllib.parse.quote(cert['name'], ''),
                                             cert_id=str(data.getName()[-3]),
                                             **cert_request))
        mail.send(msg)

        mongo.db.requests.remove(cert_request)

        return "OK. Certificate has been approved and notification sent to the requester"

#############################################################################################
# Helpers
#############################################################################################

def generate_token():
    return ''.join([random.choice(string.ascii_letters + string.digits) for n in range(60)])

def ndnify(dnsName):
    ndnName = ndn.Name()
    for component in reversed(dnsName.split(".")):
        ndnName = ndnName.append(str(component))
    return ndnName

def get_operator_for_email(email):
    # very basic pre-validation
    user, domain = email.split('@', 2)
    operator = mongo.db.operators.find_one({'site_emails': {'$in':[ domain ]}})
    if (operator == None):
        operator = mongo.db.operators.find_one({'site_emails': {'$in':[ 'guest' ]}})

        if (operator == None):
            raise Exception("Unknown site for domain [%s]" % domain)

        # Special handling for guests
        ndn_domain = ndn.Name("/ndn/guest")
        assigned_namespace = ndn.Name('/ndn/guest')
        assigned_namespace.append(str(email))
    else:
        if domain == "operators.named-data.net":
            ndn_domain = ndn.Name(str(user))
            assigned_namespace = ndn.Name(str(user))
        else:
            ndn_domain = ndnify(domain)
            assigned_namespace = ndn.Name('/ndn')
            assigned_namespace \
                .append(ndn_domain) \
                .append(str(user))

    # return various things
    return {'operator':operator, 'user':user, 'domain':domain, 'requestDetails':True,
            'ndn_domain':ndn_domain, 'assigned_namespace':assigned_namespace}

def get_operator_for_guest_site(email, site_prefix):
    operator = mongo.db.operators.find_one({'site_prefix': site_prefix, 'allowGuests': True})
    if (operator == None):
        raise Exception("Invalid site")

    assigned_namespace = ndn.Name(site_prefix)
    assigned_namespace \
      .append("@GUEST") \
      .append(email)

    # return various things
    return {'operator':operator, 'user':None, 'domain':None, 'requestDetails':False,
            'ndn_domain':site_prefix, 'assigned_namespace':assigned_namespace}

if __name__ == '__main__':
    app.run(debug = True, host='0.0.0.0')
