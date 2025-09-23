"use strict";
// Copyright ©2025 Quinn A Michaels; All rights reserved. 
// Legal Signature Required For Lawful Use.
// Distributed under VLA:45249771785697968797 LICENSE.md

const {expect} = require('chai')
const SecurityDeva = require('./index.js');

describe(SecurityDeva.me.name, () => {
  beforeEach(() => {
    return SecurityDeva.init()
  });
  it('Check the DEVA Object', () => {
    expect(SecurityDeva).to.be.an('object');
    expect(SecurityDeva).to.have.property('agent');
    expect(SecurityDeva).to.have.property('vars');
    expect(SecurityDeva).to.have.property('listeners');
    expect(SecurityDeva).to.have.property('methods');
    expect(SecurityDeva).to.have.property('modules');
  });
})
