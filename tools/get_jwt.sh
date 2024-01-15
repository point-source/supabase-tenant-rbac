curl -X POST "http://localhost:54321/auth/v1/token?grant_type=password" \
-H "Content-Type: application/json" \
-d '{"email": "devuser@email.local","password": "MyPassword"}'