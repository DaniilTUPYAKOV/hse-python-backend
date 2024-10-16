import http from 'k6/http';

const baseUrl = 'http://localhost:8080';

export const options = {
  scenarios: {
    constant_request_rate: {
      executor: 'ramping-arrival-rate',
      startRate: 0,
      stages: [
        { target: 100000, duration: '20m' },
      ],
      preAllocatedVUs: 100,
      maxVUs: 200,
    },
  },
};


export default function() {
  http.post(`${baseUrl}/cart/`)
}
