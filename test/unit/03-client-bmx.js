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
var test = require('tape');

var FabricClient = require('../..');
var client;

var fabricSettings = {
    //host: 'localhost',
    host: '2a5515c3-f5bd-4c93-87e9-134d8623dc78_vp1-discovery.blockchain.ibm.com',
    port: 30303,
    tlsRequired: true,
    security: {
        enabled: true,
        level: 256,
        privacy: false
    },
    memberSvcSettings: {
        //host: "localhost",
        //port: 50051
        secure: true,
        host: '2a5515c3-f5bd-4c93-87e9-134d8623dc78_ca-api.blockchain.ibm.com',
        port: 30303
    },
    tCertBatchSize: 10
};

/** 
var memberSvcSettings = {
    host: "localhost",
    port: 50051
    //secure: true,
    //host: '3150d9c2-f0e7-4c39-ac4e-c30062877cb5_ca-api.blockchain.ibm.com',
    //port: 30303
};
*/

var testUser = {
    identity: "testUser" + Date.now(),
    role: 1,
    account: "group1",
    affiliation: "00001"
};

test('Create Fabric Client', function (t) {
    t.plan(1);
    try {
        client = new FabricClient.Client(fabricSettings);
        //handle some events for logging
        client.on("metadata", function (metadata) {
            console.log('chat metadata event:\n', JSON.stringify(metadata, null, 4));
        });
        t.pass('created fabric client');
    }
    catch (err) {
        t.fail('failed to create farbic client: ', err);
    }


})

/** 
test('Invoke Unsecure Transaction', function (t) {
    t.plan(1);
    debug('testUser.certs:\n', testUser.certs);
    var chaincodeSpec = new FabricClient.ChaincodeSpec();
    chaincodeSpec.setType(FabricClient.ChaincodeSpec.Type.GOLANG);
    chaincodeSpec.setChaincodeID({ name: 'mychaincode' });
    chaincodeSpec.setCtorMsg({ function: 'myfunction', args: ['arg1', 'arg2'] });
    var chaincodeInvocationSpec = new FabricClient.ChaincodeInvocationSpec();
    chaincodeInvocationSpec.setChaincodeSpec(chaincodeSpec);
    client.invoke(chaincodeInvocationSpec, function (err, response) {
        if (err) {
            t.fail('failed to invoke chaincode: ' + response);
        }
        else {
            t.pass('successfully invoked chaincode: ' + response);
        }
    })

});
*/
test('Register and enroll',function(t){
    
    t.plan(1);
    
    client.registerAndEnroll(testUser,function(err){
        if (err){
            t.fail('failed to register and enroll: ' + err);
        }
        else
        {
            t.pass('successful registration and enrollment');
        }
    })
    
});

test('Invoke Secure Transaction', function (t) {
    t.plan(1);
    debug('client.tCertBatch:\n', client.tCertBatch);
    var chaincodeSpec = new FabricClient.ChaincodeSpec();
    chaincodeSpec.setType(FabricClient.ChaincodeSpec.Type.GOLANG);
    chaincodeSpec.setChaincodeID({ name: 'mychaincode' });
    chaincodeSpec.setCtorMsg({ function: 'myfunction', args: ['arg1', 'arg2'] });
    var chaincodeInvocationSpec = new FabricClient.ChaincodeInvocationSpec();
    chaincodeInvocationSpec.setChaincodeSpec(chaincodeSpec);
    client.invoke(chaincodeInvocationSpec, function (err, response) {
        if (err) {
            t.fail('failed to invoke chaincode: ' + response);
        }
        else {
            t.pass('successfully invoked chaincode: ' + response);
        }
    })

});

test('Shutdown client', function (t) {
    t.plan(1);

    try {
        client.end();
        t.pass('successfully shutdown client');
    }
    catch (err) {
        t.fail('failed to shutdown client: ', err);
        process.exit();
    }

});

/**
test('Get Transaction Certificates', function (t) {

    t.plan(1);
    //get transaction certs and then run tests
    getTCerts(testUser, function (err, key, certs) {

        if (err) {
            t.fail('failed to retrieve transaction certificates: ', err);
        }
        else {
            debug('tcerts:\n', certs);
            testUser.key = key;
            testUser.certs = certs;
            t.pass('retrieved transaction certificates');
        }

    })

});
*/
