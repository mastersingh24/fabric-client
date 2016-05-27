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

//setup asn1js and pkijs for use in Node
var debug = require('debug')('x509');
var merge = require("node.extend");

var common = require("asn1js/org/pkijs/common");
var _asn1js = require("asn1js");
var _pkijs = require("pkijs");
var _x509schema = require("pkijs/org/pkijs/x509_schema");

// #region Merging function/object declarations for ASN1js and PKIjs  
var asn1js = merge(true, _asn1js, common);

var x509schema = merge(true, _x509schema, asn1js);

var pkijs_1 = merge(true, _pkijs, asn1js);
var pkijs = merge(true, pkijs_1, x509schema);

//utility function to convert Node buffers to Javascript arraybuffer
X509Certificate.prototype._toArrayBuffer = function(buffer) {
    var ab = new ArrayBuffer(buffer.length);
    var view = new Uint8Array(ab);
    for (var i = 0; i < buffer.length; ++i) {
        view[i] = buffer[i];
    }
    return ab;
};

//utility function to convert Javascript arraybuffer to Node buffers
X509Certificate.prototype._toBuffer = function(ab) {
    var buffer = new Buffer(ab.byteLength);
    var view = new Uint8Array(ab);
    for (var i = 0; i < buffer.length; ++i) {
        buffer[i] = view[i];
    }
    return buffer;
};

function X509Certificate(buffer) {
    debug('cert:',JSON.stringify(buffer));
    //convert certBuffer to arraybuffer
    var certBuffer = this._toArrayBuffer(buffer);
    //parse the DER-encoded buffer
    var asn1 = pkijs.org.pkijs.fromBER(certBuffer);
    //this._cert = {};
    try {
        this._cert = new pkijs.org.pkijs.simpl.CERT({ schema: asn1.result });
        debug('decoded certificate:\n', JSON.stringify(this._cert, null, 4));
    }
    catch (ex) {
        debug('error parsing certificate bytes: ', ex)
        throw ex;
    }

};

X509Certificate.prototype.criticalExtension = function(oid){
    
    var ext;
    debug('oid: ',oid);
    this._cert.extensions.some(function(extension){
        
        debug('extnID: ',extension.extnID);
        if (extension.extnID===oid){
            ext = extension;
            return true;
        }
    });
    debug('found extension: ',ext);
    debug('extValue: ',this._toBuffer(ext.extnValue.value_block.value_hex));
    return this._toBuffer(ext.extnValue.value_block.value_hex);
    
}

module.exports = X509Certificate;