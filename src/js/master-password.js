/*******************************************************************************

    uBlock Origin - a browser extension to block requests.
    Copyright (C) 2026-present Raymond Hill

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see {http://www.gnu.org/licenses/}.

******************************************************************************/

const PBKDF2_ITERATIONS = 600000;
const MASTER_PASSWORD_VERSION = 1;

const toHex = bytes => {
    return Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('');
};

const fromHex = hex => {
    if ( typeof hex !== 'string' || hex.length % 2 !== 0 ) { return null; }
    const bytes = new Uint8Array(hex.length / 2);
    for ( let i = 0; i < hex.length; i += 2 ) {
        bytes[i / 2] = Number.parseInt(hex.slice(i, i + 2), 16);
    }
    return bytes;
};

const deriveVerifier = async function(password, saltHex) {
    if ( typeof password !== 'string' || password.length === 0 ) { return null; }
    const salt = fromHex(saltHex);
    if ( salt === null ) { return null; }

    const keyMaterial = await crypto.subtle.importKey(
        'raw',
        new TextEncoder().encode(password),
        'PBKDF2',
        false,
        [ 'deriveBits', 'deriveKey' ]
    );

    const key = await crypto.subtle.deriveKey(
        {
            name: 'PBKDF2',
            hash: 'SHA-256',
            salt,
            iterations: PBKDF2_ITERATIONS,
        },
        keyMaterial,
        { name: 'HMAC', hash: 'SHA-256' },
        false,
        [ 'sign', 'verify' ]
    );

    const verifier = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode('uBO-master-password'));
    return toHex(new Uint8Array(verifier));
};

export const createMasterPasswordRecord = async function(password) {
    if ( typeof password !== 'string' || password.length === 0 ) { return null; }

    const saltBytes = crypto.getRandomValues(new Uint8Array(16));
    const saltHex = toHex(saltBytes);
    const verifier = await deriveVerifier(password, saltHex);
    if ( verifier === null ) { return null; }

    return {
        version: MASTER_PASSWORD_VERSION,
        salt: saltHex,
        verifier,
    };
};

export const verifyMasterPassword = async function(password, record) {
    if ( typeof password !== 'string' || password.length === 0 ) { return false; }
    if ( record instanceof Object === false ) { return false; }

    const { version, salt, verifier } = record;
    if ( version !== MASTER_PASSWORD_VERSION ) { return false; }
    if ( typeof salt !== 'string' || typeof verifier !== 'string' ) { return false; }
    if ( salt.length === 0 || verifier.length === 0 ) { return false; }

    const expectedVerifier = await deriveVerifier(password, salt);
    return typeof expectedVerifier === 'string' && expectedVerifier === verifier;
};

export default {
    createMasterPasswordRecord,
    verifyMasterPassword,
};
