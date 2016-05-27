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
var debug = require('debug')('crypto');
var test = require('tape');
var ecdsa = require('../../lib/crypto').ecdsa;
var EC = require('elliptic').ec;



var msg = 'this is a test';



test('ECDSA Signature - level 256',function(t){
    t.plan(1);
    
    var keys = new EC('p256').genKeyPair();
    debug('private key: ',keys.getPrivate('hex'))
    try {
        ecdsa.sign(256,keys.getPrivate('hex'),msg)
        t.pass('valid 256 signature');
    }
    catch (err) {
        t.fail('invalid 256 signature: '+ err);
    }
});

test('ECDSA Signature - level 384',function(t){
    t.plan(1);
    
    var keys = new EC('p384').genKeyPair();
    debug('private key: ',keys.getPrivate('hex'))
    try {
        ecdsa.sign(384,keys.getPrivate('hex'),msg)
        t.pass('valid 384 signature');
    }
    catch (err) {
        t.fail('invalid 384 signature: '+ err);
    }
});