import http from 'k6/http';
import { check, sleep } from 'k6';

export const options = {
  scenarios: {
    smoke_auth_and_users: {
      executor: 'constant-vus',
      vus: 20,
      duration: '2m',
    },
  },
  thresholds: {
    http_req_failed: ['rate<0.01'],
    'http_req_duration{endpoint:login}': ['p(95)<250'],
    'http_req_duration{endpoint:users}': ['p(95)<200'],
  },
};

const baseUrl = __ENV.BASE_URL || 'http://localhost:3000';

function randomEmail(prefix = 'load') {
  return `${prefix}-${__VU}-${__ITER}@example.com`;
}

export default function smokeScenario() {
  const registerPayload = JSON.stringify({
    email: randomEmail('register'),
    name: 'Load Tester',
    password: 'StrongPassword123!',
  });

  const registerResponse = http.post(`${baseUrl}/api/auth/register`, registerPayload, {
    headers: { 'content-type': 'application/json' },
    tags: { endpoint: 'register' },
  });
  check(registerResponse, { 'register status is 201': (r) => r.status === 201 });

  const loginPayload = JSON.stringify({
    email: randomEmail('login'),
    name: 'Load Login User',
    password: 'StrongPassword123!',
  });

  const preRegister = http.post(`${baseUrl}/api/auth/register`, loginPayload, {
    headers: { 'content-type': 'application/json' },
    tags: { endpoint: 'register' },
  });
  check(preRegister, { 'pre-register status is 201': (r) => r.status === 201 });

  const loginResponse = http.post(
    `${baseUrl}/api/auth/login`,
    JSON.stringify({
      email: JSON.parse(loginPayload).email,
      password: 'StrongPassword123!',
    }),
    {
      headers: { 'content-type': 'application/json' },
      tags: { endpoint: 'login' },
    }
  );

  check(loginResponse, { 'login status is 200': (r) => r.status === 200 });
  const accessToken = loginResponse.json('data.access_token');

  const usersResponse = http.get(`${baseUrl}/api/users?page=1&limit=10`, {
    headers: {
      Authorization: `Bearer ${accessToken}`,
    },
    tags: { endpoint: 'users' },
  });

  check(usersResponse, {
    'users request returns expected auth status': (r) => r.status === 200 || r.status === 403,
  });

  sleep(1);
}
