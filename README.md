# keycloak-conditional-apicheck

*Condition - API Check* module to be used in the authentication flow

This project is an easy way to allows you to deport the condition analysis to an external API


## Build 

### Git Clone
`git clone https://github.com/gmc44/keycloak-conditional-apicheck.git`

### Package
To build the JAR module, invoke
```sh
mvn package
```

This will download all required dependencies and build the JAR in the `target` directory.

## Installation

1. Create a new directory `providers` in your Keycloak installation dir (if not already existing).
2. Restart keycloak

A new "Condition - API Check" is then available in the authentication flow configuration.

## Usage example

conditional OTP authentication :
That is: A user shall be required to perform a multi-factor authentication (password + OTP), when he is located externally (= has foreign IP address).

With that, the final authentication sub-flow for performing the conditional password + OTP authentication looks like this:

- Sub-Flow: "Conditional OTP Flow" (Type: Flow; Requirement: Conditional)
  - Execution: "Condition - Check API" (Type: Authenticator.Conditional; Requirement: Required; Configuration:)
  - Execution: "MFA Login" (Type: Authenticator; Requirement: Required)

Configuration for "Condition - Check API":
![configuration](doc/Condition%20-%20API%20Check%20-%20IpIsNotSecure.png?raw=true "configuration")

## Api example
![swagger](doc/Condition%20-%20API%20Check%20-%20Swagger.png?raw=true "swagger")

Response should be :
-200 : True
-401 : False
-other : default

see https://github.com/gmc44/mfalogin-api

## Release History

* 1.0
    * Initial release