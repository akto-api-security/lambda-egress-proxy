# Lambda HTTPS proxy

This container runs `mitmdump` on port `3128` and validates Amazon Bedrock
runtime requests and responses with Akto.

## Build and run

```sh
docker build -t lambda-proxy .

docker run --name lambda-proxy --restart unless-stopped \
  -p 3128:3128 \
  -e AKTO_AUTHORIZATION='YOUR_AKTO_AUTHORIZATION' \
  -e AKTO_ACCOUNT_ID='1726615470' \
  -e AKTO_VXLAN_ID='8a4028fae71a58398112daf2def8b3df' \
  lambda-proxy
```

Set the Lambda function's `HTTPS_PROXY` environment variable to the EC2
instance's reachable address, for example `http://10.0.1.25:3128`.

For HTTPS interception, install the mitmproxy CA certificate generated in the
container at `/root/.mitmproxy/mitmproxy-ca-cert.pem` in the Lambda runtime.
Lambda's outbound security-group rules must allow TCP `3128` to the
EC2 instance, and the EC2 security group should allow TCP `3128` only from the
Lambda security group.

The container logs validation failures and returns HTTP `403` for blocked
requests or responses. Akto validation calls bypass the proxy to avoid a
request loop.