"use strict";
// ©2025 Quinn A Michaels; All rights reserved. 
// Legal Signature Required For Lawful Use.
// Distributed under VLA:65538593067641220245 LICENSE.md

const {expect} = require('chai')
const :key: = require('./index.js');

describe(:key:.me.name, () => {
  beforeEach(() => {
    return :key:.init()
  });
  it('Check the DEVA Object', () => {
    expect(:key:).to.be.an('object');
    expect(:key:).to.have.property('agent');
    expect(:key:).to.have.property('vars');
    expect(:key:).to.have.property('listeners');
    expect(:key:).to.have.property('methods');
    expect(:key:).to.have.property('modules');
  });
})
