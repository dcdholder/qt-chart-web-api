import os
import sys
import urllib.parse
import json
import string
import random
import hashlib
from datetime import datetime, timedelta

from flask import Flask, request, send_file
from flask_restful import Api, Resource
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS

qtChartWebApp = Flask(__name__)
#chartApp.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.abspath(os.path.dirname(os.path.realpath(__file__))) + '/charts.db'
db = SQLAlchemy(qtChartWebApp)
CORS(qtChartWebApp)

class FormatResource():
    def get(self,versionId):
        requestJson = request.get_json()

        if versionId in Format.allVersions():
            return Format.getVersion(versionId), 200
        else:
            return 'Chart version \'' + versionId + '\' does not exist.', 404

#initially we support basic CRUD with 'login' and 'logout'
#login and logout are 'post' and 'delete' requests, respectively
class UserResource():
    def get(self, action):
        requestJson = request.get_json()

        if action=="read":
            if "username" in requestJson.keys():
                if UserCredentials.usernameExists(requestJson["username"]):
                    userData = UserData.get(requestJson["username"])
                    return userData, 200
                else:
                    return 'User \'' + requestJson["username"] + '\' does not exist.', 404
            else:
                return 'Missing username.', 400
        else:
            return 'Invalid get request action.', 400

    def post(self, action):
        requestJson = request.get_json()

        if action=="login" or action=="logon": #create a session id, store and return it
            if ("username" in requestJson.keys()) and ("password" in requestJson.keys()):
                if UserCredentials.loginCredentialsExist(requestJson["username"],requestJson["password"]):
                    sessionCredentials = UserSessions.new(requestJson["userData"])
                    return sessionCredentials, 201 #returns the username and session token
                else:
                    return 'Incorrect username or password.' 403
            else:
                return 'Missing username or password field.', 400

        elif action=="create": #create a new user with the specified form data
            if ("username" in requestJson.keys()) and ("password" in requestJson.keys()) and ("userData" in requestJson.keys()):
                if !UserCredentials.usernameExists(requestJson["username"]):
                    if UserCredentials.usernameFormatValid(requestJson["username"]) and UserCredentials.passwordFormatValid(requestJson["password"]):
                        if UserData.isValid(requestJson["userData"]):
                            UserCredentials.new(requestJson["username"],requestJson["password"])
                            UserData.new(requestJson["username"],requestJson["userData"])
                            sessionCredentials = UserSessions.new(requestJson["username"])

                            return sessionCredentials, 201
                        else:
                            return 'User data format is invalid.', 403
                    else:
                        return 'Invalid username or password format.', 403
                else:
                    return 'User \'' + requestJson["username"] + '\' already exists.', 403
            else:
                return 'Missing username, password or user data fields.', 400

        elif action=="update": #update a user's data
            if ("sessionId" in requestJson.keys()) and ("userData" in requestJson.keys()):
                if UserSessions.sessionExists(requestJson["sessionId"]):
                    if UserData.isValid(requestJson["userData"]):
                        username           = UserSessions.usernameFromSessionId(requestJson["sessionId"])
                        sessionCredentials = UserSessions.refresh(requestJson["sessionId"])
                        UserData.refresh(username,requestJson["userData"])

                        return sessionCredentials, 200
                    else:
                        return 'User data format is invalid.', 403
                else:
                    return 'Session ID is either invalid, or has expired.', 403
            else:
                return 'Missing session id or user data fields.', 400

        else:
            return 'Invalid post request action.', 400

    def delete(self, action):
        reqestJson = request.get_json()

        if action=="logout": #delete all session data
            if "sessionId" in requestJson.keys():
                if UserSessions.sessionExists(requestJson["sessionId"]):
                    username = UserSessions.usernameFromSessionId(requestJson["sessionId"])
                    UserSessions.remove(username) #note: this deletes ALL open sessions for the user!

                    return 'Logged user \'' + username + '\' out successfully.', 204
                else:
                    return 'No session to log out from.', 204

        elif action=="delete": #delete user
            if "username" in requestJson.keys():
                if UserCredentials.usernameExists(requestJson["username"]):
                    UserData.remove(requestJson["username"])
                    UserCredentials.remove(requestJson["username"])
                    UserSessions.remove(requestJson["username"])

                    return '', 204
                else:
                    return 'User \'' + requestJson["username"] + '\' does not exist.', 404
            else:
                return 'Missing username field.', 400

        else:
            return 'Invalid delete request action.', 400

class Format(db.Model):
    version     = db.Column(db.String(100), primary_key=True)
    chartFormat = db.Column(db.Text, unique=False)

    def __init__(self,version,chartFormat):

    def allVersions():
        return db.session.query(Format.version).all()

    def getVersion(version):
        return db.session.query(Format.chartFormat).filter_by(version=version)

#use one-to-one relationships between anything with a username column
class UserCredentials(db.Model):
    PASSWORD_SALT_SIZE = 32

    username     = db.Column(db.String(100), primary_key=True)
    passwordSalt = db.Column(db.String(100), unique=False)
    passwordHash = db.Column(db.String(100), unique=False)

    def __init__(self,username,password):
        self.username     = username
        self.passwordSalt = binascii.hexlify(os.urandom(UserCredentials.PASSWORD_SALT_SIZE))
        self.passwordHash = UserCredentials.getPasswordHash(password,self.passwordSalt)

    def new(username,password):
        if UserCredentials.usernameFormatValid(username) and UserCredentials.passwordFormatValid(password):
            db.session.add(username,password)
            db.session.commit()
        else:
            raise ValueError('New user credentials are invalid.')

    def remove(username):
        UserCredentials.query.filter_by(username=username).delete()
        db.session.commit()

    def usernameExists(username):
        extantUserCredentials = UserCredentials.query.filter_by(username=username).first()

        return extantUserCredentials!=None

    def loginCredentialsExist(username,password):
        extantUserCredentials = UserCredentials.query.filter_by(username=username)

        return UserCredentials.getPasswordHash(password,extantUserCredentials.passwordSalt)==extantUserCredentials.passwordHash:


    #TODO: implement these two!
    def usernameFormatValid(username):
        pass

    def passwordFormatValid(password):
        pass

    def getPasswordHash(password,passwordSalt):
        return hashlib.sha224(password.encode("utf8") + passwordSalt.encode("utf8")).hexdigest()

class UserData(db.Model):
    username     = db.Column(db.String(100), primary_key=True)
    userData     = db.Column(db.Text, unique=False) #TODO: tricky JSON storage
    creationDate = db.Column(db.DateTime, unique=False)
    updateDate   = db.Column(db.DateTime, unique=False)

    def __init__(self,username,userData):
        self.username = username
        self.userData = userData
        self.creationDate = datetime.utcnow()
        self.updateDate   = datetime.utcnow()

    def new(username,userData):
        if UserData.isValid(userData):
            db.session.add(UserData(username,userData))
            db.session.commit()
        else:
            raise ValueError('New user data is invalid.')

    def get(username):
        dataEntry = UserData.query.filter_by(username=username).first()

        if dataEntry!=None:
            return dataEntry.userData
        else:
            raise ValueError('Invalid username.')

    def refresh(username,userData):
        if UserData.isValid(userData):
            dataEntry = UserData.query.filter_by(username=username).first()
            dataEntry.updateDate = datetime.utcnow()
            db.session.commit()
        else:
            raise ValueError('Updated user data is invalid.')

    def remove(username):
        UserData.query.filter_by(username=username).delete()
        db.session.commit()

    def isValid(userData): #TODO: implement this!
        pass

# TODO: expired sessions should be cleared as a cron job or something
class UserSessions(db.Model):
    SESSION_ID_BYTE_SIZE   = 32
    MAX_SESSIONS_PER_USER  = 3
    EXPIRY_TIME_IN_SECONDS = 60*60*24*7 #one week

    username   = db.Column(db.String(100), primary_key=True)
    sessionId  = db.Column(db.String(100), unique=True)
    expiryDate = db.Column(db.DateTime, unique=False)

    def __init__(self,username):
        self.username   = username
        self.sessionId  = binascii.hexlify(os.urandom(UserSessions.SESSION_ID_BYTE_SIZE))
        self.expiryDate = datetime.utcnow() + timedelta(seconds=UserSessions.EXPIRY_TIME_IN_SECONDS)

    def new(username): # create a new session
        #delete oldest session if there's no more room
        extantSessions = UserSessions.query.filter_by(username=username).order_by(UserSessions.expiryDate.asc())
        if extantSessions.length > UserSessions.MAX_SESSIONS_PER_USER:
            db.session.delete(extantSessions[0])

        newSession = UserSessions(username)
        db.session.add(newSession)
        db.session.commit()

        return newSession.sessionId

    def refresh(sessionId): # remove session specified by id, add and return a new one
        oldSession = UserSessions.query.filter_by(sessionId=sessionId).first()
        newSession = UserSessions(oldSession.username)
        db.session.delete(oldSession)
        db.session.add(newSession)
        db.session.commit()

        return newSession.sessionId

    def remove(username): # remove all user sessions
        UserSessions.query.filter_by(username=username).delete()
        db.session.commit()

    def sessionExists(sessionId):
        sessionIdCount = UserSessions.query.filter_by(sessionId=sessionId).count()

        return sessionIdCount==1

    def usernameFromSessionId(sessionId):
        userSession = UserSessions.query.filter_by(sessionId=sessionId).first()

        return userSession.username

    def clearExpiredSessions(): #TODO: figure out how to run this externally, if it's possible
        UserSessions.query.filter_by(expiryDate<=datetime.utcnow()).delete()

db.create_all()

qtChartWebApi = Api(qtChartWebApp)
qtChartWebApi.add_resource(UserResource,   '/user/<action>')
qtChartWebApi.add_resource(FormatResource, '/format/<versionId>')

if __name__ == '__main__':
    chartApp.run(debug=True)
