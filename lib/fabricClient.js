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

var debug = require('debug')('client');
var EventEmitter = require('events').EventEmitter;
var util = require('util');
var uuid = require('uuidv4');
//grpc
var grpc = require('grpc');
var protoFile = __dirname + "/protos/api.proto";
var Timestamp = grpc.load(__dirname + "/protos/google/protobuf/timestamp.proto").google.protobuf.Timestamp;
//load the protobuf definitions
var protos = grpc.load(protoFile).protos;
var MemberSvcs = require('./memberSvcs');

//crypto
var sjcl = require('sjcl');
var crypto = require('./crypto');
var ecdsa = crypto.ecdsa;
var hmac = crypto.hmac;
var X509Certificate = crypto.X509Certificate;
var aes = crypto.aes;
var BN = require('bn.js');


function FabricClient(settings) {


    this.grpcServerAddress = settings.host + ":" + settings.port;
    if (settings.tlsRequired) {
        this.grpcCredentials = grpc.credentials.createSsl();
    }
    else {
        this.grpcCredentials = grpc.credentials.createInsecure();
    };

    this.secure = settings.security.enabled || false;
    this.securityLevel = settings.security.level || null;

    //create client and start chat
    this.peerClient = new protos.Peer(this.grpcServerAddress, this.grpcCredentials);
    this.streamClient = this.peerClient.chat()

    //for convenience bind events and methods to ourself
    var self = this;
    var methods = ['end', 'write'];
    methods.forEach(function (method) {
        self[method] = function () {
            self.streamClient[method].apply(self.streamClient, arguments);
        };
    })
    var events = ['data', 'end', 'metadata', 'status'];
    events.forEach(function (event) {
        self.streamClient.on(event, self.emit.bind(self, event));
    });

    //initialize memberSvcs
    this.memberSvcs = new MemberSvcs(settings.memberSvcSettings);
    
    this.tCertBatchSize = settings.tCertBatchSize;

};

//implement EventEmitter interface
util.inherits(FabricClient, EventEmitter);

FabricClient.prototype.registerAndEnroll = function (user, callback) {
    var self = this;

    //this.user = user;
    this.enrollID = user.identity;

    this.memberSvcs.registerAndEnroll(user, function (err, enrollKey, enrollCert, enrollChainKey) {

        if (err) {
            debug('Error registering and enrolling %s: %s', user.enrollID, err);
            callback(err);
        }
        else {
            self.enrollKey = enrollKey;
            self.enrollCert = enrollCert;
            self.enrollChainKey = enrollChainKey;

            //get a batch of tcerts
            self.getTCertBatch(self.tCertBatchSize, function (err) {
                if (err) {
                    callback(err);
                }
                else {
                    callback();
                }
            })

        }

    });

};

FabricClient.prototype.getTCertBatch = function (num, callback) {

    var self = this;
    this.memberSvcs.getTCertBatch(self.enrollID, self.enrollKey, num, function (err, key, tcerts) {
        if (this.err) {
            debug('Failed to get transaction certs for %s: %s', self.enrollID, err);
            callback(err);
        }
        else {

            //derive secret keys for tcerts
            self.tCertOwnerKDFKey = key;
            debug('self.tCertOwnerKDFKey: ', JSON.stringify(self.tCertOwnerKDFKey));

            var byte1 = new Buffer(1);
            byte1.writeUInt8(0x1);
            var byte2 = new Buffer(1);
            byte2.writeUInt8(0x2);
            //buf1[0]=1;
            debug('byte1: ', JSON.stringify(byte1));
            debug('byte2: ', JSON.stringify(byte2));


            var tCertOwnerEncryptKey = hmac.hmac(self.tCertOwnerKDFKey, byte1, self.securityLevel).slice(0, 32);
            var expansionKey = hmac.hmac(self.tCertOwnerKDFKey, byte2, self.securityLevel);
            debug('tCertOwnerEncryptKey: ', tCertOwnerEncryptKey);
            debug('tCertOwnerEncryptKey length: ', tCertOwnerEncryptKey.length);
            debug('expansionKey: ', expansionKey);
            debug('expansionKey length: ', expansionKey.length);

            self.tCertBatch = [];
            //var x509Certificate, tCertIndexCT, tCertIndex;
            var tCertIndexCT, tCertIndex;
            //loop through certs and extract private keys
            tcerts.forEach(function (tcert, index) {
                debug('tcert %d: ', index, tcert);
                console.log('tcert ', index);
                //X509Certificate = {};
                try {
                    var x509Certificate = new X509Certificate(new Buffer(tcert.cert));
                    //extract the encrypted bytes from extension attribute
                    tCertIndexCT = x509Certificate.criticalExtension(crypto.constants.TCertEncTCertIndex);
                    //debug('tCertIndexCT: ',JSON.stringify(tCertIndexCT));
                    tCertIndex = aes.CBCPKCS7Decrypt(tCertOwnerEncryptKey, tCertIndexCT);
                    //debug('tCertIndex: ',JSON.stringify(tCertIndex));

                    var expansionValue = crypto.hmac.hmac(expansionKey, tCertIndex, self.securityLevel);
                    //debug('expansionValue: ',expansionValue);

                    //compute the private key
                    var one = new BN(1);
                    var k = new BN(expansionValue);
                    //debug('k: ',k.toString());
                    //debug('enroll key hex: ',self.enrollKey);
                    //debug('enroll private key: ',ecdsa.keyFromPrivate(self.enrollKey,self.securityLevel,'hex').getPrivate());
                    //debug('enroll key N: ',ecdsa.keyFromPrivate(self.enrollKey,self.securityLevel,'hex').ec.curve.n);
                    var n = ecdsa.keyFromPrivate(self.enrollKey, self.securityLevel, 'hex').ec.curve.n.sub(one);
                    //debug('n: ',n.toString());
                    k = k.mod(n);
                    k = k.add(one);
                    //debug('k: ',k.toString());

                    var D = ecdsa.keyFromPrivate(self.enrollKey, self.securityLevel, 'hex').getPrivate().add(k);
                    //debug('pub: ',ecdsa.keyFromPrivate(self.enrollKey,self.securityLevel,'hex').getPublic());
                    var pubHex = ecdsa.keyFromPrivate(self.enrollKey, self.securityLevel, 'hex').getPublic('hex');
                    //debug('enroll public key N: ',ecdsa.keyFromPublic(pubHex,self.securityLevel,'hex').ec.curve.n);
                    D = D.mod(ecdsa.keyFromPublic(pubHex, self.securityLevel, 'hex').ec.curve.n);
                    //debug('D: ',D.toString());

                    var tCertStruct = {};
                    tCertStruct.privateKey = ecdsa.keyFromPrivate(D, self.securityLevel);
                    debug('tCert.privateKey', tCertStruct.privateKey);
                    debug('tCert.privateKey.publicKey');
                    tCertStruct.publicKey = tcert.cert;
                    self.tCertBatch.push(tCertStruct);
                }
                catch (ex) {
                    console.log("error parsing transaction certificate bytes: ",ex,tcert.cert.toString('hex'))
                }

            })

            callback();
        }
    })
};

FabricClient.prototype.getPeers = function () {


};

/**
 * Deploy chaincode to the blockchain
 */
FabricClient.prototype.deploy = function () {

};

/**
 * Chat with peer
 */
FabricClient.prototype.chatWithPeer = function (message, callback) {
    this.once('data', function (ocRespMsg) {

        debug('raw response:\n ', ocRespMsg);

        var response = protos.Response.decode(ocRespMsg.payload);
        debug('\ndecoded response msg:\n ', response.msg);
        debug('\ndecoded response msg buffer slice:\n ', response.msg.buffer.slice(response.msg.offset).toString());
        var status = null;
        switch (response.status) {
            case protos.Response.StatusCode.FAILURE:
                debug('invoke failure');
                status = protos.Response.StatusCode.FAILURE;
                break;
            case protos.Response.StatusCode.SUCCESS:
                debug('invoke success');
                break;
            case protos.Response.StatusCode.UNDEFINED:
                debug('invoke undefined');
                status = protos.Response.StatusCode.UNDEFINED;
                break;
        }
        callback(status, response.msg.buffer.slice(response.msg.offset).toString());
    });
    this.write(message);

};


/**
 * Invoke a chaincode function
 */
FabricClient.prototype.invoke = function (chaincodeInvocationSpec, callback) {

    var transaction = new protos.Transaction({
        type: protos.Transaction.Type.CHAINCODE_EXECUTE,
        timestamp: new Timestamp({ seconds: Date.now() / 1000, nanos: 0 }),
        chaincodeID: chaincodeInvocationSpec.chaincodeSpec.chaincodeID.toBuffer(),
        payload: chaincodeInvocationSpec.toBuffer(),
        uuid: uuid()
    });

    if (this.secure) {
        //sign the transaction with a tcert

        //get the current tCert
        var tCert = this.tCertBatch[0];
        transaction.setCert(tCert.publicKey);

        //sign the transaction bytes
        var txBytes = transaction.toBuffer();
        var signature = ecdsa.sign(this.securityLevel, tCert.privateKey.getPrivate('hex'), txBytes);
        //debug('signature: ',signature.toDER());

        transaction.setSignature(new Buffer(signature.toDER()));

        var openchainMessage = new protos.Message({
            type: protos.Message.Type.CHAIN_TRANSACTION,
            timestamp: new Timestamp({ seconds: Date.now() / 1000, nanos: 0 }),
            payload: transaction.toBuffer()
        });


        this.chatWithPeer(openchainMessage, function (status, response) {
            callback(status, response);
        });
    }
    else {
        var openchainMessage = new protos.Message({
            type: protos.Message.Type.CHAIN_TRANSACTION,
            timestamp: new Timestamp({ seconds: Date.now() / 1000, nanos: 0 }),
            payload: transaction.toBuffer()
        });


        this.chatWithPeer(openchainMessage, function (status, response) {
            callback(status, response);
        });
    }


};

/**
 * Query chaincode state
 */
FabricClient.prototype.query = function (chaincodeInvocationSpec) {

};

module.exports.Client = FabricClient;
//export the specific proto messages needed by the client
module.exports.ChaincodeInvocationSpec = protos.ChaincodeInvocationSpec;
module.exports.ChaincodeSpec = protos.ChaincodeSpec;



