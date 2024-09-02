# SOA-Progetto
## Indice

- [Project Specification](#project-specification)
- [Getting Started](#getting-started)

  - [Installation](#installation)
  - [Main features](#main-features)
  - [Testing](#testing)
   
# Project Specification

 Kernel Level Reference Monitor for File Protection
This specification is related to a Linux Kernel Module (LKM) implementing a reference monitor for file protection. The reference monitor can be in one of the following four states:

  - OFF, meaning that its operations are currently disabled;
  - ON, meaning that its operations are currently enabled;
  - REC-ON/REC-OFF, meaning that it can be currently reconfigured (in either ON or OFF mode). 

The configuration of the reference monitor is based on a set of file system paths. Each path corresponds to a file/dir that cannot be currently opened in write mode. Hence, any attempt to write-open the path needs to return an error, independently of the user-id that attempts the open operation.

Reconfiguring the reference monitor means that some path to be protected can be added/removed. In any case, changing the current state of the reference monitor requires that the thread that is running this operation needs to be marked with effective-user-id set to root, and additionally the reconfiguration requires in input a password that is reference-monitor specific. This means that the encrypted version of the password is maintained at the level of the reference monitor architecture for performing the required checks.

It is up to the software designer to determine if the above states ON/OFF/REC-ON/REC-OFF can be changed via VFS API or via specific system-calls. The same is true for the services that implement each reconfiguration step (addition/deletion of paths to be checked). Together with kernel level stuff, the project should also deliver user space code/commands for invoking the system level API with correct parameters.

In addition to the above specifics, the project should also include the realization of a file system where a single append-only file should record the following tuple of data (per line of the file) each time an attempt to write-open a protected file system path is attempted:

  - the process TGID
  - the thread ID
  - the user-id
  - the effective user-id
  - the program path-name that is currently attempting the open
  - a cryptographic hash of the program file content 

The the computation of the cryptographic hash and the writing of the above tuple should be carried in deferred work. 

# Getting Started

## Installation
Clone the repository
```shell
https://github.com/creccovalerio/SOA-Progetto.git
```

Enter the repository `/reference-monitor` and execute the following command:
```shell
sudo sh launch.sh
```
Executing this command, all the modules (the_reference_monitor, the_usctm, singlefilefs) will be loaded in the system and the reference monitor is ACTIVE but there aren't default blacklisted files or directories.

## Main Features
Moving into the directory `/reference-monitor/user`, you can access the reference monitor main features lauching the following commands:
```shell
make all
```
```shell
sudo ./user
```
If you don't launch `./user` using  `sudo`, the features of the reference monitor will return an error, beacuse the thread that is running this operations needs to be marked with effective-user-id set to `root`. It's also necessary to specify a password at the beginnig of each operations. 

The main operations offered by the reference monitor are:
 - Change the reference monitor to ON;
 - Change the reference monitor to OFF;
 - Change the reference monitor to REC-ON;
 - Change the reference monitor to REC-OFF;
 - Add a new file or directory path into the blacklist;
 - Remove a file or directory path from the blacklist;
 - Update the password;

## Testing
Moving into the directory `/reference-monitor/user/test`, you can access the reference monitor tester lauching the following commands:
```shell
make all
```
```shell
./testing
```
In this repository there are the folders `files` or `blackdir` which contain other files or directories that can be used in order to test the reference monitor functionalities.
The reference monitor tester allow to execute the following operations:
 - Open a file;
 - Delete a file;
 - Create a directory;
 - Delete a directory;
 - Move a file or a directory into another directory;
 - Copy a file or a directory into another directory;

The previous operations will be successfully executed only if the file or the directory specified in the operations it's not inserted into the blacklist.

