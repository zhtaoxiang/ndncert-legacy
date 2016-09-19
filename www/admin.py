from flask import Blueprint, render_template, abort, request, redirect, url_for, Response, current_app
from jinja2 import TemplateNotFound
from functools import wraps
import hashlib
from bson.objectid import ObjectId

admin = Blueprint('admin', __name__, template_folder='templates')

import auth

from wtforms import Form, BooleanField, TextField, SubmitField, HiddenField, TextAreaField, validators
from wtforms.validators import *

class RegistrationForm(Form):
    _id         = HiddenField()
    site_prefix = TextField('Site Prefix', [Required()])
    site_name   = TextField('Site Name', [Required()])
    site_emails = TextField('Site Emails', [Required()])
    name        = TextField('Operator Name', [Required()])
    email       = TextField('Operator Email', [Required()])
    allowGuests = BooleanField('Allow guest accounts', false_values=[False])
    doNotSendOpRequestsForGuests = BooleanField('Disable security operator requests for guest accounts', false_values=[False])
    doNotSendOpRequests          = BooleanField('Disable all security operator requests', false_values=[False])
    key         = TextAreaField('Operator public key certificate (base64)')

class Operator(dict):
    def getlist(self, key):
        if key == 'site_emails':
            return ["; ".join(self[key])]
        else:
            return [self[key]]

    def __repr__(self):
        return type(self).__name__ + '(' + dict.__repr__(self) + ')'

@admin.route('/admin', methods = ['GET'], strict_slashes=False)
@auth.requires_auth
def list_operators():
    operators = current_app.mongo.db.operators.find({ '$query': {}, '$orderby': { 'site_prefix' : 1 } })
    return render_template('admin/list-operators.html',
                           operators=operators, title="List of registered operators")

@admin.route('/admin/add-operator', methods = ['GET', 'POST'], strict_slashes=False)
@auth.requires_auth
def add_operator():
    form = RegistrationForm(request.form)
    if request.method == 'POST' and form.validate():
        operator = form.data
        operator['site_emails'] = [s.strip() for s in operator['site_emails'].split(";")]
        current_app.mongo.db.operators.insert(operator)
        return redirect(url_for('admin.list_operators'))
    return render_template('admin/add-or-edit.html', form=form,
                           title="Add operator")


@admin.route('/admin/edit-operator/<id>', methods = ['GET', 'POST'], strict_slashes=False)
@auth.requires_auth
def edit_operator(id):
    if request.method == 'POST':
        form = RegistrationForm(request.form)
    else:
        operator = current_app.mongo.db.operators.find_one({'_id': ObjectId(id)})
        form = RegistrationForm(Operator(operator))

    if request.method == 'POST' and form.validate():

        operator = form.data
        operator['site_emails'] = [s.strip() for s in operator['site_emails'].split(";")]
        current_app.mongo.db.operators.update({'_id': ObjectId(id)},
                                              {'$set': operator},
                                              upsert=False, multi=False)

        return redirect(url_for('admin.list_operators'))

    return render_template('admin/add-or-edit.html', form=form,
                           title="Edit operator")

@admin.route('/admin/delete-operator/<id>', methods = ['GET', 'POST'], strict_slashes=False)
@auth.requires_auth
def delete_operator(id):
    current_app.mongo.db.operators.remove({'_id': ObjectId(id)})
    return redirect(url_for('admin.list_operators'))
