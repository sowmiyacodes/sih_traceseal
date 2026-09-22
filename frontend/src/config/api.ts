import axios from 'axios'

export const API_BASE = 'http://127.0.0.1:8000/api'

export const api = axios.create({ baseURL: API_BASE })

api.interceptors.request.use((config) => {
  const token = window.localStorage.getItem('traceseal_session')
  if (token) config.headers.Authorization = `Bearer ${token}`
  return config
})
