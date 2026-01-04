#!/usr/bin/bash
#

export PRIVATE_KEY="bd89cc99cec86725872410261cefddbcd156fd9a86fd2447f88ad2fc9e1e9e6f"
export RPC_URL="https://sepolia.infura.io/v3/d9a7de9928c84ecfb3470f9e71fda2e4" 
./submit_folder.sh \
  --folder $1 \
  --settings ./setup.json \
  --rpc "$RPC_URL" \
  --pk "$PRIVATE_KEY" \
  --contract 0x2594985A1963c4f7904a38aEf7e7efb830774b9f

