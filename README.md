
# ISO-9506 Manufacturing Message Specification (MMS) Rust Implementation

## Protocol

MMS was originally developed on top of the OSI seven layer network model, then adapted for use with TCP/IP, while retaining the original Transport, Session, Presentation, and ACSE layers. Each of these layers defines its own protocol primitives, encoding, and state machine. Because these protocol layers are no longer widely used, the MMS application layer is responsible for their implementation.

The following protocol layers are in use in common MMS implementations:

* Transport Service on top of TCP - ISO-8072, RFC-1006
* Transport Protocol - ISO-8073, RFC-905
* Session Protocol - ISO-8327, X.225
* Presentation Protocol - ISO-8823, X.226
* Association Control Service - ISO-8650, X.227

This library aims to implement a minimal subset of protocol functionality required for operation, while conforming to the requirements outlined in the specification and enforcing correct message structure.

### Connection Setup and Tear-down

```mermaid
sequenceDiagram
Client->>Server: TCP SYN
Server->>Client: TCP SYN-ACK
Client-->>Server: TCP ACK
activate Server
Note right of Server: TCP connected
Client->>Server: COTP Connect Request
Server-->>Client: COTP Connect Confirm
activate Server
Note right of Server: ISO Transport layer connected
Client->>Server: MMS Initiate Request
Server-->>Client: MMS Initiate Response
activate Server
Note right of Server: MMS application layer connected
loop Exchange MMS messages
Client->>Server: MMS Confirmed Request
Server-->>Client: MMS Confirmed Response
end
Note right of Server: Disconnect
Client->>Server: MMS Conclude Request
Server-->>Client: MMS Conclude Response
deactivate Server
deactivate Server
Client->>Server: TCP FIN, etc
deactivate Server
```

## Client Library

Implemented!

## Server Library

TODO

## Client Command Line Tool

Implemented!
