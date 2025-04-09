ECHO OFF
REM
REM k-rest.py REST Client Data Transfer
REM
REM This is sample batch file for demonstration purposes only.
REM
REM Please see README file at https://github.com/thalescpl-io/REST-Key-Xfer for a detailed explaination of the parameters.

REM py k-rest.py -srcHost xklm-22.test256.io -srcUser sklmrick -srcPass Thales_4567 -dstHost cm-kirk.test256.io -dstUser rest_alice -dstPass Thales234! -listSrcClients -listOnly SOURCE -resolveSrcClientOwnership
REM py k-rest.py -srcHost 192.168.1.180 -srcUser sklmrick -srcPass Thales_4567 -dstHost 192.168.1.190 -dstUser rest_alice -dstPass Thales234! -listSrcClients -listOnly SOURCE -resolveSrcClientOwnership -includeSecrets

REM py k-rest.py -srcHost xklm-22.test256.io -srcUser sklmrick -srcPass Thales_4567 -dstHost cm-kirk.test256.io -dstUser rest_alice -dstPass Thales234! -srcClientName KMIPCLIENT5 -resolveSrcClientOwnership -includeSecrets
REM py k-rest.py -srcHost xklm-22.test256.io -srcUser sklmrick -srcPass Thales_4567 -dstHost cm-kirk.test256.io -dstUser rest_alice -dstPass Thales234! -listSrcClients -srcClientName KMIPCLIENT5 -listOnly BOTH
py k-rest.py -srcHost xklm-22.test256.io -srcUser sklmrick -srcPass Thales_4567 -dstHost cm-kirk.test256.io -dstUser admin -dstPass em50-UAV2000 -listOnly DESTINATION