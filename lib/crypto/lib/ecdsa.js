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
var elliptic = require('elliptic');
var EC = elliptic.ec;
var sha3_256 = require('js-sha3').sha3_256;
var sha3_384 = require('js-sha3').sha3_384;

exports.sign = function(level,key,msg){
    var curve;
    var hash;
    
    //select curve and hash algo based on level
    switch(level)
    {
        case 256:
            curve = elliptic.curves['p256'];
            hash = sha3_256;
            break;
        case 384:
            curve = elliptic.curves['p384'];
            hash = sha3_384;
            break;
    }
    
    var ecdsa = new EC(curve);
    var signKey = ecdsa.keyFromPrivate(key, 'hex');
    var sig = ecdsa.sign(new Buffer(hash(msg), 'hex'), signKey);
    debug('ecdsa signature: ',sig)
    return sig;
       
};

exports.keyFromPrivate = function(key,level,encoding){
    
    //select curve and hash algo based on level
    switch(level)
    {
        case 256:
            curve = elliptic.curves['p256'];
            break;
        case 384:
            curve = elliptic.curves['p384'];
            break;
    };
    
    var keypair = new EC(curve).keyFromPrivate(key, encoding);;  
    debug('keypair: ',keypair) 
    return keypair;
};

exports.keyFromPublic = function(key,level,encoding){
    
    //select curve and hash algo based on level
    switch(level)
    {
        case 256:
            curve = elliptic.curves['p256'];
            break;
        case 384:
            curve = elliptic.curves['p384'];
            break;
    };
    
    var keypair = new EC(curve).keyFromPrivate(key, encoding);;  
    debug('keypair: ',keypair) 
    return keypair;
};


exports.generateKeyPair = function(level){
    
    //select curve and hash algo based on level
    switch(level)
    {
        case 256:
            curve = elliptic.curves['p256'];
            break;
        case 384:
            curve = elliptic.curves['p384'];
            break;
    };
    
    var keypair = new EC(curve).genKeyPair();  
    debug('keypair: ',keypair) 
    return keypair;
};
