# **WORK IN PROGRESS**

## Requirements
[ASP .NET Core 6.0](https://dotnet.microsoft.com/en-us/download/dotnet/thank-you/runtime-aspnetcore-6.0.21-windows-x64-installer?cid=getdotnetcore)

## privacyIDEA CA Service for Windows
This is a Windows service running a gRPC server to serve requests from privacyIDEA.
It is intended to execute certificate enrollment and enumeration of certificate related information on behalf of privacyIDEA.

The service definition is found in the [protofile](https://github.com/privacyidea/ms-ca-service/blob/main/CAService/proto/caservice.proto).
