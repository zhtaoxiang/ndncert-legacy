from flask import Blueprint, render_template, abort, request, redirect, url_for, Response, current_app, make_response
from jinja2 import TemplateNotFound
from functools import wraps
import hashlib
from bson.objectid import ObjectId
import base64

import pyndn as ndn
import pyndn.security.certificate
from datetime import datetime

cert = Blueprint('cert', __name__, template_folder='templates')

import auth

nfd_android_client = "NFD-Android"

# Public interface
@cert.route('/cert/get/', methods = ['GET'])
def get_certificate():
    client = request.args.get('client')
    name = request.args.get('name')
    isView = request.args.get('view')
    token = request.args.get('token')

    if client == nfd_android_client:
        cert = current_app.mongo.db.certs.find_one({'token': token})
        ndn_name = ndn.Name(str(cert['name']))
    else:
        ndn_name = ndn.Name(str(name))

        cert = current_app.mongo.db.certs.find_one({'name': str(name)})
    if cert == None:
        abort(404)

    if not isView:
        response = make_response(cert['cert'])
        response.headers['Content-Type'] = 'application/octet-stream'
        response.headers['Content-Disposition'] = 'attachment; filename=%s.ndncert' % str(ndn_name[-3])
        return response
    else:
        d = ndn.security.certificate.IdentityCertificate()
        d.wireDecode(bytearray(base64.b64decode(cert['cert'])))

        notBefore = datetime.utcfromtimestamp(d.getNotBefore() / 1000)
        notAfter = datetime.utcfromtimestamp(d.getNotAfter() / 1000)
        cert['from'] = notBefore
        cert['to'] = notAfter
        now = datetime.now()
        cert['isValid'] = (notBefore <= now and now <= notAfter)
        cert['info'] = d

        return render_template('cert-show.html',
                               cert=cert, title=cert['name'])


# Public interface
@cert.route('/cert/list/', methods = ['GET'])
def get_certificates():
    certificates = current_app.mongo.db.certs.find().sort([('name', 1)])
    return make_response(render_template('cert-list.txt', certificates=certificates), 200, {
            'Content-Type': 'text/plain'
            })

@cert.route('/cert/list/html', methods = ['GET'])
def list_certs_html():
    certs = current_app.mongo.db.certs.find({ '$query': {},
                                         '$orderby': { 'name' : 1, 'operator.site_prefix': 1 }})
    certsWithInfo = []
    for cert in certs:
        info = cert
        d = ndn.security.certificate.IdentityCertificate()
        d.wireDecode(bytearray(base64.b64decode(cert['cert'])))

        notBefore = datetime.utcfromtimestamp(d.getNotBefore() / 1000)
        notAfter = datetime.utcfromtimestamp(d.getNotAfter() / 1000)
        now = datetime.now()
        if notBefore <= now and now <= notAfter:
            info['to'] = notAfter.strftime('%Y-%m-%d')
            certsWithInfo.append(info)

    return render_template('cert-list.html',
                           certs=certsWithInfo, title="List of issued and not expired certificates")

@cert.route('/cert/list/admin', methods = ['GET'])
@auth.requires_auth
def list_certs_admin():
    certs = current_app.mongo.db.certs.find({ '$query': {},
                                         '$orderby': { 'name' : 1, 'operator.site_prefix': 1 }})
    return render_template('admin/cert-list.html',
                           certs=certs, title="List of issued certificates")

@cert.route('/admin/delete-cert/<id>', methods = ['GET', 'POST'])
@auth.requires_auth
def delete_cert(id):
    current_app.mongo.db.certs.remove({'_id': ObjectId(id)})
    return redirect(url_for('cert.list_certs_admin'))
