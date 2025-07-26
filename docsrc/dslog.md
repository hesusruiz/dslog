# Decentralised Scalable Tamper-evident Log

This document describes DSTLog, a mechanism to easily create tamper-evident logs implemented on top of the ISBE blockchain network. The combination of the log and blockchain provides to applications very high performance and scalability, maintaining the critical features of a blockchain, while being very simple and cheap to operate at scale. It also facilitates GDPR compliance because individual data entries can be easily deleted if required, without affecting the trust properties of the rest of the entries.

The trust guarantees that the system provides to applications are the following:

1. **Non-tampering** and **non-impersonation**: Entries written by the application can not be modified or created by the Log operator impersonating the application, because they are signed.

2. **Timestamped Proof of inclusion**: Right after an application has written an entry to the log, the application can request from the log an Inclusion Proof of the entry, which is timestamped and signed by the log operator:
   - The application can use that inclusion proof to prove to any third party that the application logged the data entry at a given time in the past.
   - The log operator can not deny that the data entry was logged, so it can be made responsible for any censorship.

3. **Global Consistency**: The log periodically publishes a Checkpoint to the ISBE Blockchain, with the period chosen to suit the specific requirements of the use case where the log is used. After a Checkpoint has been published, malicious log operators can not perform **split-view attacks**, where a malicious log presents a different view of its contents to different users (that is, each user's view of the log is consistent, but differs between users). After the Checkpoint appears in the ISBE Blockchain:
   - The Checkpoint commits to all previous entries ever written in the log, with the same entries and the same order for all users of the log.
   - The timestamp of the Checkpoint commits also all previous entries in the log since the previous Checkpoint.

The mechanisms described in this document makes the log operators non-trusted entities. That is, applications and its users do not have to trust the log operators, because any malicious behaviour is easily detected and corrected.

The only possible attack from malicious log operators is denial of service of its own log (not allowing to write or read a given entry). This is easily solved by having more than one log operator running different instances of the same log: as long as a log allows writing and reading, the system works even if all log operators are malicious. Logs are easy and cheap to operate, and any entity can operate a log, even application operators.

The above properties hold even when ALL Log operators are malicious, and the Byzantine actors can not alter the history of events or create events in the past. In other words, the system supports any number of Byzantyne actors at the level of the Log, and up to 1/3 Byzantine actors at the Blockchain level (as usual for blockchains).



The four components of the system are:

1. **Applications** which write entries to one or more logs. There can be as many logs as required, operated by different entities and for different use cases.
2. A **Personality** is the component of the log which receives the requests from Applications to add entries to the log. The Personality implements the use-case specific requirements for data model and validations before allowing an entry to be written into the underlying log.
3. The actual **Log** layer receives the data entries from Personalities and adds each one to the Log (which is implemented as a Merkle Tree).
4. The **ISBE Blockchain** layer, which receives periodic requests to store **Checkpoints** of the Log. The Checkpoints are generated periodically when a given nuber of entries have been written to the Log, or a timeout has elapsed since the last Checkpoint. Each Log can have a different timeout, depending on the specific use-case requirements).

## How it works: High level overview

The log uses the [Tessera library](https://github.com/transparency-dev/tessera), which is a Go library for building [tile-based transparency logs (tlogs)](https://c2sp.org/tlog-tiles), implementing 
[current best-practices based on the lessons learned](https://transparency.dev/articles/tile-based-logs/)
over the past decade of building and operating transparency logs in production environments and at scale.

A tamper-evident log stores an **accurate**, **immutable** and **verifiable** history of activity. You could use them to track credits and debits in banking transactions, access logs to sensitive healthcare records, cryptographic hashes of software packages, compliance artifacts of regulated activities, or modifications to a document.

The DSTLog works in the following way:

1. The applications write entries to the DSTLog, using a REST API, usually only one API. The server implements the verification requirements for the specific use case, checking that the entries are formally valid for the use case (e.g., the entry as a given data model).
2. The REST API uses [Tessera](https://github.com/transparency-dev/tessera) to store log entries with very high performance.  Tessera uses a Merkle tree to implement a [verifiable log](https://transparency.dev/verifiable-data-structures/). Every record inserted into a verifiable log is added as a new leaf in the Merkle tree. The tree head hash at the top of the tree acts as a snapshot of all the records in the log, because if any record is modified, the tree head hash changes.
3. Periodically, Tessera signs tree head hashes with a private key, creating the signed tree head (STH). The STHs are published periodically by the log to the **ISBE Witness** component, using a standard format called [Transparency Log Checkpoint](https://github.com/C2SP/C2SP/blob/main/tlog-checkpoint.md).
4. The ISBE Witness implements the [Transparency Log Witness Protocol](https://github.com/transparency-dev/witness-protocol) to receive Checkpoints from the logs. Witnesses verify that the Checkpoint is consistent with their previously recorded state of the log (if any), writes the Checkpoint to the ISBE Bare blockchain network and return a timestamped cosignature.

The ISBE Witness solves in a simple way the problem of split-view attacks, where a malicious log presents a different view of its contents to different users. That is, each user's view of the log is consistent, but differs between users.

## Types of logs

The system can be used to implement many types of logs, depending on the use case requirements. For example, Application operators may use Logs operated by themselves, or may use Logs operated by other entities. Data that the Applications want to log may contain PII, or private business data, or just public data.

We present here some examples which help describe how the provided components can be used to achieve the desired properties.

## Certificate Transparency: a Public Log

The first example is a log like in the Certificate Transparency ecosystem (CT, in short), which we describe at a high level to describe the properties of such an ecosystem. For more details, go to [How CT works](https://certificate.transparency.dev/howctworks/).

The objective of CT is to allow anyone to audit Web PKI certificate authority (CA) activity and **notice the issuance of suspect certificates** as well as to audit the certificate logs themselves. The _user agents_ (browsers like Chrome, Safari, Mozilla or Brave) refuse to honor certificates that do not appear in a log, effectively forcing CAs to add all issued certificates to the logs.

In CT, the Applications are the **Certificate Authorities** (CAs) which issue SSL certificates associated to a domain for a web site. The data entries written to the log are the **SSL certificates**, which are always public. The Log operators are entities like Google, Cloudflare or LetsEncrypt which operate distributed and independent logs.

CAs must write each issued certificate to at least two different logs, to ensure data availability. Certificate logs are append-only ledgers of certificates. Because they're distributed and independent, anyone can query them to see what certificates have been included and when.

The users of the Logs are typically, but not limited to, the _user agents_ (browsers like Chrome, Edge, Safari or Mozilla), which help enforce Certificate Transparency.

In addition, because the logs are public, they are cryptographically monitored by some entities called Monitors.

If you have a web site and subscribe to a CT monitor for your domain, you get updates when precertificates and certificates for those domains are included in any of the logs checked by that monitor. Monitors can be set up and run by anyone (including yourself).







Since 2013, 15,071,377,230 certificates have been logged.

In CT, the entries are the web certificates issued by 

As described in [RFC 6962](https://datatracker.ietf.org/doc/rfc6962/):

in a manner that allows anyone to audit
   certificate authority (CA) activity and notice the issuance of
   suspect certificates as well as to audit the certificate logs
   themselves.  The intent is that eventually clients would refuse to
   honor certificates that do not appear in a log, effectively forcing
   CAs to add all issued certificates to the logs.

   Logs are network services that implement the protocol operations for
   submissions and queries that are defined in this document.
