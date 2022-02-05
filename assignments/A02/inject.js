"use strict";

send({type: 'hello', hello_message: 'hello world'})

// Suggestions to help
var mem_allocations = {}; // Address => size. If you want
var first_allocation = true;

// Sketch of what you might want to do.
// Use interceptor to record entry and exit of malloc and free
// Use local javascript to store state between those.A
// There's an easy way to pass state between an Interpreter onEnter
// and OnLeave function you can just use `this.something` store state
// Call send() as appropriate
