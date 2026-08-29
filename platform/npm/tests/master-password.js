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

*******************************************************************************/

'use strict';

import { strict as assert } from 'assert';

import {
    createMasterPasswordRecord,
    verifyMasterPassword,
} from '../../../src/js/master-password.js';

describe('Master password', () => {
    context('password verification', () => {
        it('should accept the correct password', async () => {
            const record = await createMasterPasswordRecord('correct horse battery staple');
            assert.equal(await verifyMasterPassword('correct horse battery staple', record), true);
        });

        it('should reject a wrong password', async () => {
            const record = await createMasterPasswordRecord('correct horse battery staple');
            assert.equal(await verifyMasterPassword('wrong password', record), false);
        });

        it('should generate unique records for the same password', async () => {
            const recordA = await createMasterPasswordRecord('same password');
            const recordB = await createMasterPasswordRecord('same password');
            assert.notEqual(recordA.salt, recordB.salt);
            assert.notEqual(recordA.verifier, recordB.verifier);
            assert.equal(await verifyMasterPassword('same password', recordA), true);
            assert.equal(await verifyMasterPassword('same password', recordB), true);
        });

        it('should fail closed for malformed records', async () => {
            assert.equal(await verifyMasterPassword('any', null), false);
            assert.equal(await verifyMasterPassword('any', {}), false);
            assert.equal(await verifyMasterPassword('any', { version: 1, salt: 'abc', verifier: 'def' }), false);
        });
    });
});
