/**
 * Copyright 2016 IBM
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
*/
/**
 * Licensed Materials - Property of IBM
 * © Copyright IBM Corp. 2016
 */

var debug = require('debug')('memberSvcs');
var connector = require('../loopback-connector-obcca');

function MemberSvcs(settings) {
    var self = this;
    //initialize the obcca connector
    self.dataSource = {};
    self.dataSource.settings = settings;
    connector.initialize(self.dataSource);

};

MemberSvcs.prototype.register = function (user, callback) {

    this.dataSource.connector.registerUser(user, function (err, response) {

        if (err) {
            debug('failed to register user: ', err);
            callback(err);
        }
        else {
            //return the enrollSecret (aka token)
            callback(null, response.token);
        }
    });

};

MemberSvcs.prototype.enroll = function (enrollID, enrollSecret, callback) {

    this.dataSource.connector.getEnrollmentCertificateFromECA(
        { identity: enrollID, token: enrollSecret },
        function (err, enrollKey, enrollCert, enrollChainKey) {
            if (err) {
                debug('failed to retrieve enrollment certficate:\n', err);
                callback(err);
            }
            else {
                debug('enrollKey: ', enrollKey);
                //return enrollKey,enrollCert,enrollChainkey
                callback(null, enrollKey, enrollCert, enrollChainKey);
            }

        })
};

MemberSvcs.prototype.registerAndEnroll = function (user, callback) {
    
    var self = this;
    
    //combine register and enroll for convenience
    this.register(user, function (err, enrollSecret) {

        if (err) {
            callback(err);
        }
        else {
            //enroll
            self.enroll(user.identity, enrollSecret, function (err, enrollKey, enrollCert, enrollChainKey) {
                if (err)
                {
                    callback(err);
                }
                else
                {
                    callback(null, enrollKey, enrollCert, enrollChainKey);
                };
            })
        }

    });
};

MemberSvcs.prototype.getTCertBatch = function (enrollID, enrollKey, batchSize, callback) {

    var tCertSetRequest =
        {
            identity: enrollID,
            enrollmentKey: enrollKey,
            num: batchSize
        };

    this.dataSource.connector.tcaCreateCertificateSet(tCertSetRequest,
        function (err, key, certs) {
            if (err) {
                console.log('failed to retrieve transaction certificate set:\n', err);
                callback(err);
            }
            else {
                debug('TCert key: ', JSON.stringify(key));
                debug('TCert certs:\n', certs);
                callback(null, key, certs);
            }

        })
};




module.exports = MemberSvcs;
