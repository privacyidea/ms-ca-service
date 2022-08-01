https://grpc.io/docs/languages/python/basics/

Install grpc:
pip install grpcio-tools

Generate python code from the protofile:
python -m grpc_tools.protoc -I. --python_out=. --grpc_python_out=. .\caservice.proto

For debugging the following could be useful:

https://github.com/grpc/grpc/blob/master/TROUBLESHOOTING.md
export GRPC_VERBOSITY DEBUG
export GRPC_TRACE http
