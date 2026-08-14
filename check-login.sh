#!/bin/bash
echo "--- login with username ---"
curl -s -X POST http://localhost:5000/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"kali"}'
echo ""
echo "--- login with email ---"
curl -s -X POST http://localhost:5000/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"muhammadsaifudinmj@gmail.com","password":"kali"}'
echo ""