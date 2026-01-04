#!/usr/bin/bash
#

export PRIVATE_KEY="bd89cc99cec86725872410261cefddbcd156fd9a86fd2447f88ad2fc9e1e9e6f"
export RPC_URL="https://sepolia.infura.io/v3/d9a7de9928c84ecfb3470f9e71fda2e4" 
./register.sh \
  --checkin 30 \
  --grace 7 \
  --rpc "$RPC_URL" \
  --pk "$PRIVATE_KEY" \
  --contract 0x859be49c6C24bC7800AB02e5A2F188c8C14f23DB

