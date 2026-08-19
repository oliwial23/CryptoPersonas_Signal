Terminal 1

cd /Users/oliwiakempinski/Documents/GitHub/CryptoPersonas_Signal
rm -rf /tmp/pp-test
PERSONAS_PROFILE=local PERSONAS_BIND=127.0.0.1:3095 PERSONAS_DATA_DIR=/tmp/pp-test ./target/release/server

Terminal 2

cd /Users/oliwiakempinski/Documents/GitHub/CryptoPersonas_Signal
P=(--transport signal --api http://127.0.0.1:3095 --data-dir /tmp/pp-test-client)
./target/release/personas "${P[@]}" join
./target/release/personas "${P[@]}" priv-pass-ticket -b 42
