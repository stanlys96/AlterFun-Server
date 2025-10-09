import axios from 'axios';

import * as dotenv from 'dotenv';

dotenv.config();

export const API_BASE_URL = process.env.VITE_BASE_URL_AI;
export const API_KEY = process.env.VITE_AI_KEY;
export const API_REQUEST_FROM = process.env.VITE_REQUEST_FROM;
export const OPEN_ROUTER_API_KEY = process.env.VITE_OPEN_ROUTER_API_KEY;

export const axiosElwyn = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'X-AI_TOKEN': API_KEY,
    'X-REQUEST_FROM': API_REQUEST_FROM,
  },
});
