# Decentralised Scalable Tamper-evident Log

This document describes a tamper-evident log implemented on top of the [Tessera library](https://github.com/transparency-dev/tessera). Tessera is a Go library for building [tile-based transparency logs (tlogs)](https://c2sp.org/tlog-tiles), implementing 
[current best-practices based on the lessons learned](https://transparency.dev/articles/tile-based-logs/)
over the past decade of building and operating transparency logs in production environments and at scale.

A tamper-evident log stores an **accurate**, **immutable** and **verifiable** history of activity. You could use them to track credits and debits in banking transactions, access logs to sensitive healthcare records, cryptographic hashes of software packages, compliance artifacts of regulated activities, or modifications to a document.

The four components of the systems are:

1. Applications which write entries to one or more logs. Each log can be operated by any entity, which 

The DSTLog works in the following way:

1. The applications write entries to the DSTLog, using a REST API.
2. The REST API uses [Tessera](https://github.com/transparency-dev/tessera) to store log entries with very high performance.  Tessera uses a Merkle tree to implement a [verifiable log](https://transparency.dev/verifiable-data-structures/). Every record inserted into a verifiable log is added as a new leaf in the Merkle tree. The tree head hash at the top of the tree acts as a snapshot of all the records in the log, because if any record is modified, the tree head hash changes.
3. Periodically, Tessera signs tree head hashes with a private key, creating the signed tree head (STH). The STHs are published periodically by the log to the **ISBE Witness** component, using a standard format called [Transparency Log Checkpoint](https://github.com/C2SP/C2SP/blob/main/tlog-checkpoint.md).
4. The ISBE Witness implements the [Transparency Log Witness Protocol](https://github.com/transparency-dev/witness-protocol) to receive Checkpoints from the logs. Witnesses verify that the Checkpoint is consistent with their previously recorded state of the log (if any), writes the Checkpoint to the ISBE Bare blockchain network and return a timestamped cosignature.

The ISBE Witness solves in a simple way the problem of split-view attacks, where a malicious log presents a different view of its contents to different users. That is, each user's view of the log is consistent, but differs between users.

## Properties of the DSTLog


