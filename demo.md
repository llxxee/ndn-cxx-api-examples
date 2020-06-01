# NDN BLS Key Demo

## ndnsec tool

1. normal rsa keygen
`ndnsec-keygen -t r --keyid test /example/rsa`

2. bls keygen
`ndnsec-keygen -t b --keyid test /example/bls`
to show key generation and self-sign

3. check key already exist
`ndnsec-keygen -t b --keyid test /example/bls`
to show can successfully load bls key from backend storage

4. sign-req and cert-gen
`ndnsec-sign-req  -k /example/rsa/KEY/test`
`ndnsec-cert-gen -s /example/bls`
`ndnsec-cert-install -`
`ndnsec-dump-certificate /example/rsa/KEY/test/NA/%FD%00%00%01ro%84%BBa | base64 -D | ndn-dissect`

## Sign/Verify data and interset packet
1. `ndnsec-keygen -t b --keyid test /alice-home`
2. `ndnsec-keygen -t b --keyid test /alice-home/bedroom/sensor-1`

add trust anchor
`ndnsec-dump-certificate /alice-home/KEY/test/self/%FD%00%00%01ro%8E%8B%F0 > alice-home-anchor.cert`


`nfd-start`

1. `./controller`
2. `./tempsensor data.txt`
3. `./aircon`
