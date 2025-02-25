---
title: Introducing rgaas
published: false
---

# [RGaaS](https://github.com/gemesa/rgaas) - Random Generator as a Service 

`rgaas-server` is a service that generates random bytes (using rand() which is not a cryptographically secure generator). The length of the random byte sequence can be specified by the client. The server can handle multiple random number requests per connection, can handle multiple connections, serves the clients via TCP/IP and can be run as a daemon.

`rgaas-client` is a client to test `rgaas-server` (connect, request and display multiple random byte sequences of a user-specified length).

## Installation from source

### Prerequisites

The following tools are necessary for building:

- `cmake` (3.23)
- `clang` (14.0.5)

### How to build

Invoke the following commands:

```bash
$ cmake .
$ cmake --build .
```

which will build `rgaas-server` and `rgaas-client` executables. You can find them in the _build_ folder.

## Quickstart

Invoke the following commands (daemon mode):

```bash
$ ./build/rgaas-server -p 8000 -v -d
$ ./build/rgaas-client -n <hostname> -p 8000 -v
```

Note: you will need to send SIGINT to the process of `rgaas-server` to kill it:

```bash
$ kill -INT $(pidof ./build/rgaas-server)
```

Invoke the following commands (foreground mode):

```bash
$ ./build/rgaas-server -p 8000 -v
```
Open an other terminal:

```bash
$ ./build/rgaas-client -n <hostname> -p 8000 -v
```
## Example

```bash
$ ./build/rgaas-server -p 8000 -v
15 rgaas - program started
15 rgaas - tcp setup successful
```

```bash
$ ./build/rgaas-client -n fedora -p 8000 -v
15 rgaas - program started
13 rgaas - please enter the number of random bytes to be requested: 
100
13 rgaas - received from server:
�1X�Z%]X�^ԫ��ƛ�T�tA!=܇p�>�A��g>~���k��8\*�;�2�<T��\��C
13 rgaas - please enter the number of random bytes to be requested: 
```
