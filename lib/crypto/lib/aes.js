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

var debug = require('debug')('aes');
var aesjs = require('aes-js');

const BlockSize = 16;

function CBCDecrypt(key,bytes){
    debug('key length: ',key.length);
    debug('bytes length: ',bytes.length);
    var iv = bytes.slice(0,BlockSize);
    debug('iv length: ',iv.length);
    var encryptedBytes = bytes.slice(BlockSize);
    debug('encrypted bytes length: ',encryptedBytes.length);
    
    var decryptedBlocks = [];
    var decryptedBytes;
    
    //CBC only works with 16 bytes blocks
    if (encryptedBytes.length>BlockSize)
    {
        //CBC only support cipertext with length Blocksize
        var start = 0;
        var end = BlockSize;
        while (end <= encryptedBytes.length){
            var aesCbc = new aesjs.ModeOfOperation.cbc(key, iv);
            debug('start|end',start, end);
            var encryptedBlock = encryptedBytes.slice(start,end);
            var decryptedBlock = aesCbc.decrypt(encryptedBlock);
            debug('decryptedBlock: ',decryptedBlock);
            decryptedBlocks.push(decryptedBlock);
            //iv for next round equals previous block
            iv = encryptedBlock;
            start+=BlockSize;
            end+=BlockSize;
        };
        
        decryptedBytes = Buffer.concat(decryptedBlocks);
    }
    else
    {
        var aesCbc = new aesjs.ModeOfOperation.cbc(key, iv);
        decryptedBytes = aesCbc.decrypt(encryptedBytes);
    }
    
    debug('decrypted bytes: ',JSON.stringify(decryptedBytes));
    
    return decryptedBytes;
    
};

function CBCPKCS7Decrypt(key,bytes){
    
    var decryptedBytes;
    
    decryptedBytes = CBCDecrypt(key,bytes);
    unpaddedBytes = PKCS7UnPadding(decryptedBytes);
    
    return unpaddedBytes;      
};

function PKCS7UnPadding(bytes){
    
    //last byte is the number of padded bytes
    var padding = bytes.readUInt8(bytes.length-1);
    debug('padding: ',padding);
    //should check padded bytes, but just going to extract
    var unpadded = bytes.slice(0,bytes.length - padding);
    debug('unpadded bytes: ',JSON.stringify(unpadded));
    return unpadded;   
};

exports.CBCDecrypt = CBCDecrypt;
exports.CBCPKCS7Decrypt = CBCPKCS7Decrypt;