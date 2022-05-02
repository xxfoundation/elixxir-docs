# The xx network Gateway Node Design Specification

*version 0*

## Abstract

This document describes the xx network Gateway node design
and considers their role in our messaging system: xx messenger.

## Introduction

Clients of the xx network do not communicate directly with mix nodes.
Clients communicate directly with Gateway nodes. Besides proxying outbound
messages, Gateway nodes also collectively implement sharded message storage
for asynchronous recipient message retrieval.


